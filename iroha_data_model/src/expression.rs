//! Expressions to use inside of ISIs.
use super::{query::QueryBox, IdBox, IdentifiableBox, Parameter};
use iroha_crypto::PublicKey;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

/// Binded name for a value.
pub type ValueName = String;

/// Context, composed of (name, value) pairs.
pub type Context = BTreeMap<ValueName, Value>;

/// Boxed expression.
pub type ExpressionBox = Box<Expression>;

/// Struct for type checking and converting expression results.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct EvaluatesTo<V: TryFrom<Value>> {
    /// Expression.
    #[serde(flatten)]
    pub expression: ExpressionBox,
    #[serde(skip)]
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

impl<V: TryFrom<Value, Error = String>> Evaluate for EvaluatesTo<V> {
    type Value = V;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        self.expression
            .evaluate(world_state_view, context)?
            .try_into()
    }
}

impl Evaluate for EvaluatesTo<Value> {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        self.expression.evaluate(world_state_view, context)
    }
}

struct WorldStateView;

/// Represents all possible expressions.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub enum Expression {
    /// Add expression.
    Add(Add),
    /// Subtract expression.
    Subtract(Subtract),
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
    /// Contains all expression.
    ContainsAll(ContainsAll),
    /// Where expression to supply temporary values to local context.
    Where(Where),
    /// Get a temporary value by name
    ContextValue(ContextValue),
}

/// Boxed `Value`.
pub type ValueBox = Box<Value>;

/// Sized container for all possible values.
#[derive(Debug, Clone, Encode, Decode, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// `u32` integer.
    U32(u32),
    /// `bool` value.
    Bool(bool),
    /// `Vec` of `Value`.
    Vec(Vec<Value>),
    /// `Id` of `Asset`, `Account`, etc.
    Id(IdBox),
    /// `Identifiable` as `Asset`, `Account` etc.
    Identifiable(IdentifiableBox),
    /// `PublicKey`.
    PublicKey(PublicKey),
    /// Iroha `Parameter` variant.
    Parameter(Parameter),
}

impl TryFrom<Value> for u32 {
    type Error = String;

    fn try_from(value: Value) -> Result<u32, Self::Error> {
        if let Value::U32(value) = value {
            Ok(value)
        } else {
            Err(format!("Value {:?} is not U32.", value))
        }
    }
}

impl TryFrom<Value> for bool {
    type Error = String;

    fn try_from(value: Value) -> Result<bool, Self::Error> {
        if let Value::Bool(value) = value {
            Ok(value)
        } else {
            Err(format!("Value {:?} is not bool.", value))
        }
    }
}

impl TryFrom<Value> for Vec<Value> {
    type Error = String;

    fn try_from(value: Value) -> Result<Vec<Value>, Self::Error> {
        if let Value::Vec(value) = value {
            Ok(value)
        } else {
            Err(format!("Value {:?} is not vec.", value))
        }
    }
}

impl TryFrom<Value> for IdBox {
    type Error = String;

    fn try_from(value: Value) -> Result<IdBox, Self::Error> {
        if let Value::Id(value) = value {
            Ok(value)
        } else {
            Err(format!("Value {:?} is not an id.", value))
        }
    }
}

impl TryFrom<Value> for IdentifiableBox {
    type Error = String;

    fn try_from(value: Value) -> Result<IdentifiableBox, Self::Error> {
        if let Value::Identifiable(value) = value {
            Ok(value)
        } else {
            Err(format!("Value {:?} is not an identifiable entity.", value))
        }
    }
}

impl TryFrom<Value> for PublicKey {
    type Error = String;

    fn try_from(value: Value) -> Result<PublicKey, Self::Error> {
        if let Value::PublicKey(value) = value {
            Ok(value)
        } else {
            Err(format!("Value {:?} is not a public key.", value))
        }
    }
}

impl TryFrom<Value> for Parameter {
    type Error = String;

    fn try_from(value: Value) -> Result<Parameter, Self::Error> {
        if let Value::Parameter(value) = value {
            Ok(value)
        } else {
            Err(format!("Value {:?} is not a parameter.", value))
        }
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Value {
        Value::U32(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Value {
        Value::Bool(value)
    }
}

impl From<Parameter> for Value {
    fn from(value: Parameter) -> Value {
        Value::Parameter(value)
    }
}

impl<V: Into<Value>> From<Vec<V>> for Value {
    fn from(values: Vec<V>) -> Value {
        Value::Vec(values.into_iter().map(|value| value.into()).collect())
    }
}

impl<T: Into<Value>> From<T> for ExpressionBox {
    fn from(value: T) -> Self {
        Expression::Raw(Box::new(value.into())).into()
    }
}

trait Evaluate {
    type Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String>;
}

impl Evaluate for Expression {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        match self {
            Expression::Add(add) => add.evaluate(world_state_view, context),
            Expression::Subtract(subtract) => subtract.evaluate(world_state_view, context),
            Expression::Greater(greater) => greater.evaluate(world_state_view, context),
            Expression::Less(less) => less.evaluate(world_state_view, context),
            Expression::Equal(equal) => equal.evaluate(world_state_view, context),
            Expression::Not(not) => not.evaluate(world_state_view, context),
            Expression::And(and) => and.evaluate(world_state_view, context),
            Expression::Or(or) => or.evaluate(world_state_view, context),
            Expression::If(if_expression) => if_expression.evaluate(world_state_view, context),
            Expression::Raw(value) => Ok(*value.clone()),
            Expression::Query(_query) => unimplemented!(),
            Expression::Contains(contains) => contains.evaluate(world_state_view, context),
            Expression::ContainsAll(contains_all) => {
                contains_all.evaluate(world_state_view, context)
            }
            Expression::Where(where_expression) => {
                where_expression.evaluate(world_state_view, context)
            }
            Expression::ContextValue(context_value) => {
                context_value.evaluate(world_state_view, context)
            }
        }
    }
}

/// Get a temporary value by name.
/// The values are brought into [`Context`] by [`Where`] expression.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct ContextValue {
    /// Name binded to the value.
    pub value_name: String,
}

impl ContextValue {
    /// Constructs `ContextValue`.
    pub fn new(value_name: &str) -> Self {
        Self {
            value_name: value_name.to_string(),
        }
    }
}

impl Evaluate for ContextValue {
    type Value = Value;

    fn evaluate(
        &self,
        _world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        context
            .get(&self.value_name)
            .ok_or_else(|| format!("Value with name {} not found in context", self.value_name))
            .map(|value| value.to_owned())
    }
}

impl From<ContextValue> for ExpressionBox {
    fn from(expression: ContextValue) -> Self {
        Expression::ContextValue(expression).into()
    }
}

/// Evaluates to the sum of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Add {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Add {
    /// Constructs `Add` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl Evaluate for Add {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let left = self.left.evaluate(world_state_view, context)?;
        let right = self.right.evaluate(world_state_view, context)?;
        Ok((left + right).into())
    }
}

impl From<Add> for ExpressionBox {
    fn from(expression: Add) -> Self {
        Expression::Add(expression).into()
    }
}

/// Evaluates to the difference of right and left expressions.
/// Works only for `Value::U32`
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Subtract {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Subtract {
    /// Constructs `Subtract` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl Evaluate for Subtract {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let left = self.left.evaluate(world_state_view, context)?;
        let right = self.right.evaluate(world_state_view, context)?;
        Ok((left - right).into())
    }
}

impl From<Subtract> for ExpressionBox {
    fn from(expression: Subtract) -> Self {
        Expression::Subtract(expression).into()
    }
}

/// Returns whether the `left` expression is greater than the `right`.
/// Works only for `Value::U32`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Greater {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Greater {
    /// Constructs `Greater` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl Evaluate for Greater {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let left = self.left.evaluate(world_state_view, context)?;
        let right = self.right.evaluate(world_state_view, context)?;
        Ok((left > right).into())
    }
}

impl From<Greater> for ExpressionBox {
    fn from(expression: Greater) -> Self {
        Expression::Greater(expression).into()
    }
}

/// Returns whether the `left` expression is less than the `right`.
/// Works only for `Value::U32`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Less {
    /// Left operand.
    pub left: EvaluatesTo<u32>,
    /// Right operand.
    pub right: EvaluatesTo<u32>,
}

impl Less {
    /// Constructs `Less` expression.
    pub fn new<L: Into<EvaluatesTo<u32>>, R: Into<EvaluatesTo<u32>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl Evaluate for Less {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let left = self.left.evaluate(world_state_view, context)?;
        let right = self.right.evaluate(world_state_view, context)?;
        Ok((left < right).into())
    }
}

impl From<Less> for ExpressionBox {
    fn from(expression: Less) -> Self {
        Expression::Less(expression).into()
    }
}

/// Negates the result of the `expression`.
/// Works only for `Value::Bool`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Not {
    /// Expression that should evaluate to `Value::Bool`.
    pub expression: EvaluatesTo<bool>,
}

impl Not {
    /// Constructs `Not` expression.
    pub fn new<E: Into<EvaluatesTo<bool>>>(expression: E) -> Self {
        Self {
            expression: expression.into(),
        }
    }
}

impl Evaluate for Not {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let expression = self.expression.evaluate(world_state_view, context)?;
        Ok((!expression).into())
    }
}

impl From<Not> for ExpressionBox {
    fn from(expression: Not) -> Self {
        Expression::Not(expression).into()
    }
}

/// Applies the logical `and` to two `Value::Bool` operands.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct And {
    /// Left operand.
    pub left: EvaluatesTo<bool>,
    /// Right operand.
    pub right: EvaluatesTo<bool>,
}

impl And {
    /// Constructs `And` expression.
    pub fn new<L: Into<EvaluatesTo<bool>>, R: Into<EvaluatesTo<bool>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl Evaluate for And {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let left = self.left.evaluate(world_state_view, context)?;
        let right = self.right.evaluate(world_state_view, context)?;
        Ok((left && right).into())
    }
}

impl From<And> for ExpressionBox {
    fn from(expression: And) -> Self {
        Expression::And(expression).into()
    }
}

/// Applies the logical `or` to two `Value::Bool` operands.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Or {
    /// Left operand.
    pub left: EvaluatesTo<bool>,
    /// Right operand.
    pub right: EvaluatesTo<bool>,
}

impl Or {
    /// Constructs `Or` expression.
    pub fn new<L: Into<EvaluatesTo<bool>>, R: Into<EvaluatesTo<bool>>>(left: L, right: R) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }
}

impl Evaluate for Or {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let left = self.left.evaluate(world_state_view, context)?;
        let right = self.right.evaluate(world_state_view, context)?;
        Ok((left || right).into())
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
    pub fn build(self) -> Result<If, String> {
        if let (Some(then_expression), Some(else_expression)) =
            (self.then_expression, self.else_expression)
        {
            Ok(If::new(self.condition, then_expression, else_expression))
        } else {
            Err("Not all fields are filled.".to_string())
        }
    }
}

/// If expression. Returns either a result of `then_expression`, or a result of `else_expression`
/// based on the `condition`.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct If {
    /// Condition expression, which should evaluate to `Value::Bool`.
    pub condition: EvaluatesTo<bool>,
    /// Expression evaluated and returned if the condition is `true`.
    pub then_expression: EvaluatesTo<Value>,
    /// Expression evaluated and returned if the condition is `false`.
    pub else_expression: EvaluatesTo<Value>,
}

impl If {
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

impl Evaluate for If {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let condition = self.condition.evaluate(world_state_view, context)?;
        if condition {
            self.then_expression.evaluate(world_state_view, context)
        } else {
            self.else_expression.evaluate(world_state_view, context)
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
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Contains {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value>>,
    /// Element expression.
    pub element: EvaluatesTo<Value>,
}

impl Contains {
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

impl Evaluate for Contains {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let collection = self.collection.evaluate(world_state_view, context)?;
        let element = self.element.evaluate(world_state_view, context)?;
        Ok(collection.contains(&element).into())
    }
}

impl From<Contains> for ExpressionBox {
    fn from(expression: Contains) -> Self {
        Expression::Contains(expression).into()
    }
}

/// `Contains` expression.
/// Returns `true` if `collection` contains all `elements`, `false` otherwise.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct ContainsAll {
    /// Expression, which should evaluate to `Value::Vec`.
    pub collection: EvaluatesTo<Vec<Value>>,
    /// Expression, which should evaluate to `Value::Vec`.
    pub elements: EvaluatesTo<Vec<Value>>,
}

impl ContainsAll {
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

impl Evaluate for ContainsAll {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let collection = self.collection.evaluate(world_state_view, context)?;
        let elements = self.elements.evaluate(world_state_view, context)?;
        Ok(elements
            .iter()
            .all(|element| collection.contains(element))
            .into())
    }
}

impl From<ContainsAll> for ExpressionBox {
    fn from(expression: ContainsAll) -> Self {
        Expression::ContainsAll(expression).into()
    }
}

/// Returns `true` if `left` operand is equal to the `right` operand.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Equal {
    /// Left operand.
    pub left: EvaluatesTo<Value>,
    /// Right operand.
    pub right: EvaluatesTo<Value>,
}

impl Equal {
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

impl Evaluate for Equal {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let left = self.left.evaluate(world_state_view, context)?;
        let right = self.right.evaluate(world_state_view, context)?;
        Ok((left == right).into())
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
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Where {
    /// Expression to be evaluated.
    pub expression: EvaluatesTo<Value>,
    /// Context values for the context binded to their `String` names.
    pub values: BTreeMap<ValueName, EvaluatesTo<Value>>,
}

impl Where {
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

impl Evaluate for Where {
    type Value = Value;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        let additional_context: Result<Context, String> = self
            .values
            .clone()
            .into_iter()
            .map(|(value_name, expression)| {
                expression
                    .evaluate(world_state_view, context)
                    .map(|expression_result| (value_name, expression_result))
            })
            .collect();
        self.expression.evaluate(
            world_state_view,
            &context
                .clone()
                .into_iter()
                .chain(additional_context?.into_iter())
                .collect(),
        )
    }
}

impl From<Where> for ExpressionBox {
    fn from(where_expression: Where) -> Self {
        Expression::Where(where_expression).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;

    /// Example taken from [whitepaper](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/iroha_2_whitepaper.md#261-multisignature-transactions)
    #[test]
    fn conditional_multisignature_quorum() -> Result<(), String> {
        let asset_quantity_high = Value::U32(750);
        let asset_quantity_low = Value::U32(300);
        let key_pair_teller_1 = KeyPair::generate()?;
        let key_pair_teller_2 = KeyPair::generate()?;
        let key_pair_manager = KeyPair::generate()?;
        let teller_signatory_set = Value::Vec(vec![
            Value::PublicKey(key_pair_teller_1.clone().public_key),
            Value::PublicKey(key_pair_teller_2.public_key),
        ]);
        let one_teller_set = Value::Vec(vec![Value::PublicKey(key_pair_teller_1.public_key)]);
        let manager_signatory = Value::PublicKey(key_pair_manager.public_key);
        let manager_signatory_set = Value::Vec(vec![manager_signatory.clone()]);
        let condition: ExpressionBox = IfBuilder::condition(And::new(
            Greater::new(ContextValue::new("usd_quantity"), 500),
            Less::new(ContextValue::new("usd_quantity"), 1000),
        ))
        .then_expression(Or::new(
            ContainsAll::new(
                ContextValue::new("signatories"),
                teller_signatory_set.clone(),
            ),
            Contains::new(ContextValue::new("signatories"), manager_signatory),
        ))
        .else_expression(true)
        .build()?
        .into();
        // Signed by all tellers
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value(
                //TODO: use query to get the actual quantity of an asset from WSV
                "usd_quantity".to_string(),
                asset_quantity_high.clone(),
            )
            .with_value("signatories".to_string(), teller_signatory_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by manager
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_string(), asset_quantity_high.clone())
            .with_value("signatories".to_string(), manager_signatory_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by one teller
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_string(), asset_quantity_high.clone())
            .with_value("signatories".to_string(), one_teller_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(false)
        );
        // Signed by one teller with less value
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_string(), asset_quantity_low.clone())
            .with_value("signatories".to_string(), one_teller_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        Ok(())
    }

    #[test]
    fn where_expression() -> Result<(), String> {
        assert_eq!(
            WhereBuilder::evaluate(ContextValue::new("test_value"))
                .with_value("test_value".to_string(), Add::new(2, 3))
                .build()
                .evaluate(&WorldStateView, &Context::new())?,
            Value::U32(5)
        );
        Ok(())
    }

    #[test]
    fn nested_where_expression() -> Result<(), String> {
        let expression = WhereBuilder::evaluate(ContextValue::new("a"))
            .with_value("a".to_string(), 2)
            .build();
        let outer_expression: ExpressionBox =
            WhereBuilder::evaluate(Add::new(expression, ContextValue::new("b")))
                .with_value("b".to_string(), 4)
                .build()
                .into();
        assert_eq!(
            outer_expression.evaluate(&WorldStateView, &Context::new())?,
            Value::U32(6)
        );
        Ok(())
    }

    #[test]
    fn if_condition_builder_builds_only_with_both_branches() {
        let _ = IfBuilder::condition(true)
            .then_expression(1)
            .build()
            .expect_err("Builder should fail if a branch is missing");
        let _ = IfBuilder::condition(true)
            .else_expression(2)
            .build()
            .expect_err("Builder should fail if a branch is missing");
        let _ = IfBuilder::condition(true)
            .then_expression(1)
            .else_expression(2)
            .build()
            .expect("Builder should build if both branches are present.");
    }

    #[test]
    fn if_condition_branches_correctly() -> Result<(), String> {
        assert_eq!(
            If::new(true, 1, 2).evaluate(&WorldStateView, &Context::new())?,
            Value::U32(1)
        );
        assert_eq!(
            If::new(false, 1, 2).evaluate(&WorldStateView, &Context::new())?,
            Value::U32(2)
        );
        Ok(())
    }

    #[test]
    fn wrong_operand_types_are_caught() {
        assert!(Add::new(10, true)
            .evaluate(&WorldStateView, &Context::new())
            .expect_err("Should not be possible to add int and bool.")
            .ends_with("is not U32."));
        assert!(Subtract::new(10, true)
            .evaluate(&WorldStateView, &Context::new())
            .expect_err("Should not be possible to subtract int and bool.")
            .ends_with("is not U32."));
        assert!(And::new(1, Vec::<Value>::new())
            .evaluate(&WorldStateView, &Context::new())
            .expect_err("Should not be possible to apply logical and to int and vec.")
            .ends_with("is not bool."));
        assert!(Or::new(1, Vec::<Value>::new())
            .evaluate(&WorldStateView, &Context::new())
            .expect_err("Should not be possible to apply logical or to int and vec.")
            .ends_with("is not bool."));
        assert!(Greater::new(1, Vec::<Value>::new())
            .evaluate(&WorldStateView, &Context::new())
            .expect_err("Should not be possible to apply greater sign to int and vec.")
            .ends_with("is not U32."));
        assert!(Less::new(1, Vec::<Value>::new())
            .evaluate(&WorldStateView, &Context::new())
            .expect_err("Should not be possible to apply greater sign to int and vec.")
            .ends_with("is not U32."));
        assert!(If::new(1, 2, 3)
            .evaluate(&WorldStateView, &Context::new())
            .expect_err("If condition should be bool")
            .ends_with("is not bool."));
    }

    #[test]
    fn operations_are_correctly_calculated() -> Result<(), String> {
        assert_eq!(
            Add::new(1, 2).evaluate(&WorldStateView, &Context::new())?,
            Value::U32(3)
        );
        assert_eq!(
            Subtract::new(7, 2).evaluate(&WorldStateView, &Context::new())?,
            Value::U32(5)
        );
        assert_eq!(
            Greater::new(1, 2).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Greater::new(2, 1).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Less::new(1, 2).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Less::new(2, 1).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Equal::new(1, 2).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Equal::new(vec![1, 3, 5], vec![1, 3, 5]).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Contains::new(vec![1, 3, 5], 3).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Contains::new(vec![1, 3, 5], 7).evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            ContainsAll::new(vec![1, 3, 5], vec![1, 5])
                .evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            ContainsAll::new(vec![1, 3, 5], vec![1, 5, 7])
                .evaluate(&WorldStateView, &Context::new())?,
            Value::Bool(false)
        );
        Ok(())
    }

    #[test]
    fn serde_serialization_works() {
        let expression: ExpressionBox = Add::new(1, Subtract::new(7, 4)).into();
        let serialized_expression =
            serde_json::to_string(&expression).expect("Failed to serialize.");
        let deserialized_expression: ExpressionBox =
            serde_json::from_str(&serialized_expression).expect("Failed to deserialize.");
        assert_eq!(
            expression
                .evaluate(&WorldStateView, &Context::new())
                .expect("Failed to calculate."),
            deserialized_expression
                .evaluate(&WorldStateView, &Context::new())
                .expect("Failed to calculate.")
        )
    }

    #[test]
    fn scale_codec_serialization_works() {
        let expression: ExpressionBox = Add::new(1, Subtract::new(7, 4)).into();
        let serialized_expression: Vec<u8> = expression.encode();
        let deserialized_expression = ExpressionBox::decode(&mut serialized_expression.as_slice())
            .expect("Failed to decode.");
        assert_eq!(
            expression
                .evaluate(&WorldStateView, &Context::new())
                .expect("Failed to calculate."),
            deserialized_expression
                .evaluate(&WorldStateView, &Context::new())
                .expect("Failed to calculate.")
        )
    }
}
