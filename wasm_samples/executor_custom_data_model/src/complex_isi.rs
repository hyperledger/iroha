//! Example of custom expression system.
//! Only few expressions are implemented to show proof-of-concept.
//! See `wasm_samples/executor_custom_instructions_complex`.
//! This is simplified version of expression system from Iroha v2.0.0-pre-rc.20

pub use evaluate::*;
pub use expression::*;
pub use isi::*;

mod isi {
    use alloc::{boxed::Box, format, string::String, vec::Vec};

    use iroha_data_model::{
        isi::{CustomInstruction, Instruction, InstructionBox},
        prelude::JsonString,
    };
    use iroha_schema::IntoSchema;
    use serde::{Deserialize, Serialize};

    use crate::complex_isi::expression::EvaluatesTo;

    #[derive(Debug, Deserialize, Serialize, IntoSchema)]
    pub enum CustomInstructionExpr {
        Core(CoreExpr),
        If(Box<ConditionalExpr>),
        // Other custom instructions
    }

    impl From<CoreExpr> for CustomInstructionExpr {
        fn from(isi: CoreExpr) -> Self {
            Self::Core(isi)
        }
    }

    impl From<ConditionalExpr> for CustomInstructionExpr {
        fn from(isi: ConditionalExpr) -> Self {
            Self::If(Box::new(isi))
        }
    }

    impl Instruction for CustomInstructionExpr {}
    impl Instruction for ConditionalExpr {}
    impl Instruction for CoreExpr {}

    impl From<CustomInstructionExpr> for CustomInstruction {
        fn from(isi: CustomInstructionExpr) -> Self {
            let payload = serde_json::to_value(&isi)
                .expect("INTERNAL BUG: Couldn't serialize custom instruction");

            Self::new(payload)
        }
    }

    impl From<CustomInstructionExpr> for InstructionBox {
        fn from(isi: CustomInstructionExpr) -> Self {
            Self::Custom(isi.into())
        }
    }

    impl From<CoreExpr> for InstructionBox {
        fn from(isi: CoreExpr) -> Self {
            Self::Custom(CustomInstructionExpr::from(isi).into())
        }
    }

    impl From<ConditionalExpr> for InstructionBox {
        fn from(isi: ConditionalExpr) -> Self {
            Self::Custom(CustomInstructionExpr::from(isi).into())
        }
    }

    impl TryFrom<&JsonString> for CustomInstructionExpr {
        type Error = serde_json::Error;

        fn try_from(payload: &JsonString) -> serde_json::Result<Self> {
            serde_json::from_str::<Self>(payload.as_ref())
        }
    }

    // Built-in instruction (can be evaluated based on query values, etc)
    #[derive(Debug, Deserialize, Serialize, IntoSchema)]
    pub struct CoreExpr {
        pub object: EvaluatesTo<InstructionBox>,
    }

    impl CoreExpr {
        pub fn new(object: impl Into<EvaluatesTo<InstructionBox>>) -> Self {
            Self {
                object: object.into(),
            }
        }
    }

    /// Composite instruction for a conditional execution of other instructions.
    #[derive(Debug, Deserialize, Serialize, IntoSchema)]
    pub struct ConditionalExpr {
        /// Condition to be checked.
        pub condition: EvaluatesTo<bool>,
        /// Instruction to be executed if condition pass.
        pub then: CustomInstructionExpr,
    }

    impl ConditionalExpr {
        pub fn new(
            condition: impl Into<EvaluatesTo<bool>>,
            then: impl Into<CustomInstructionExpr>,
        ) -> Self {
            Self {
                condition: condition.into(),
                then: then.into(),
            }
        }
    }
}

mod expression {
    use alloc::{
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use core::marker::PhantomData;

    use iroha_data_model::{
        isi::InstructionBox,
        prelude::{FindAssetQuantityById, FindTotalAssetQuantityByAssetDefinitionId, Numeric},
    };
    use iroha_schema::{IntoSchema, TypeId};
    use serde::{Deserialize, Serialize};

    /// Struct for type checking and converting expression results.
    #[derive(Debug, Deserialize, Serialize, TypeId)]
    pub struct EvaluatesTo<V> {
        #[serde(flatten)]
        pub(crate) expression: Box<Expression>,
        type_: PhantomData<V>,
    }

    impl<V> EvaluatesTo<V> {
        pub fn new_unchecked(expression: impl Into<Expression>) -> Self {
            Self {
                expression: Box::new(expression.into()),
                type_: PhantomData,
            }
        }
    }

    /// Represents all possible queries returning a numerical result.
    #[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
    pub enum NumericQuery {
        FindAssetQuantityById(FindAssetQuantityById),
        FindTotalAssetQuantityByAssetDefinitionId(FindTotalAssetQuantityByAssetDefinitionId),
    }

    impl From<FindAssetQuantityById> for NumericQuery {
        fn from(value: FindAssetQuantityById) -> Self {
            Self::FindAssetQuantityById(value)
        }
    }

    impl From<FindTotalAssetQuantityByAssetDefinitionId> for NumericQuery {
        fn from(value: FindTotalAssetQuantityByAssetDefinitionId) -> Self {
            Self::FindTotalAssetQuantityByAssetDefinitionId(value)
        }
    }

    /// Represents all possible expressions.
    #[derive(Debug, Deserialize, Serialize, IntoSchema)]
    pub enum Expression {
        /// Raw value.
        Raw(Value),
        /// Greater expression.
        Greater(Greater),
        /// Query to Iroha state.
        Query(NumericQuery),
    }

    /// Returns whether the `left` expression is greater than the `right`.
    #[derive(Debug, Deserialize, Serialize, IntoSchema)]
    pub struct Greater {
        pub left: EvaluatesTo<Numeric>,
        pub right: EvaluatesTo<Numeric>,
    }

    impl Greater {
        /// Construct new [`Greater`] expression
        pub fn new(
            left: impl Into<EvaluatesTo<Numeric>>,
            right: impl Into<EvaluatesTo<Numeric>>,
        ) -> Self {
            Self {
                left: left.into(),
                right: right.into(),
            }
        }
    }

    impl From<Greater> for EvaluatesTo<bool> {
        fn from(expression: Greater) -> Self {
            let expression = Expression::Greater(expression);
            EvaluatesTo::new_unchecked(expression)
        }
    }

    /// Sized container for all possible values.
    #[derive(Debug, Clone, Deserialize, Serialize, IntoSchema)]
    pub enum Value {
        Bool(bool),
        Numeric(Numeric),
        InstructionBox(InstructionBox),
    }

    impl From<bool> for Value {
        fn from(value: bool) -> Self {
            Value::Bool(value)
        }
    }

    impl From<Numeric> for EvaluatesTo<Numeric> {
        fn from(value: Numeric) -> Self {
            let value = Value::Numeric(value);
            let expression = Expression::Raw(value);
            EvaluatesTo::new_unchecked(expression)
        }
    }

    impl From<InstructionBox> for EvaluatesTo<InstructionBox> {
        fn from(value: InstructionBox) -> Self {
            let value = Value::InstructionBox(value);
            let expression = Expression::Raw(value);
            EvaluatesTo::new_unchecked(expression)
        }
    }

    impl TryFrom<Value> for bool {
        type Error = String;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            match value {
                Value::Bool(value) => Ok(value),
                _ => Err("Expected bool".to_string()),
            }
        }
    }

    impl TryFrom<Value> for Numeric {
        type Error = String;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            match value {
                Value::Numeric(value) => Ok(value),
                _ => Err("Expected Numeric".to_string()),
            }
        }
    }

    impl TryFrom<Value> for InstructionBox {
        type Error = String;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            match value {
                Value::InstructionBox(value) => Ok(value),
                _ => Err("Expected InstructionBox".to_string()),
            }
        }
    }

    impl<V: TryFrom<Value> + IntoSchema> IntoSchema for EvaluatesTo<V> {
        fn type_name() -> String {
            format!("EvaluatesTo<{}>", V::type_name())
        }
        fn update_schema_map(map: &mut iroha_schema::MetaMap) {
            const EXPRESSION: &str = "expression";

            if !map.contains_key::<Self>() {
                map.insert::<Self>(iroha_schema::Metadata::Struct(
                    iroha_schema::NamedFieldsMeta {
                        declarations: vec![iroha_schema::Declaration {
                            name: String::from(EXPRESSION),
                            ty: core::any::TypeId::of::<Expression>(),
                        }],
                    },
                ));

                Expression::update_schema_map(map);
            }
        }
    }
}

mod evaluate {
    use alloc::string::ToString;

    use iroha_data_model::{isi::error::InstructionExecutionError, ValidationFail};

    use crate::complex_isi::{
        expression::{EvaluatesTo, Expression, Greater, Value},
        NumericQuery,
    };

    pub trait Evaluate {
        /// The resulting type of the expression.
        type Value;

        /// Calculate result.
        fn evaluate(&self, context: &impl Context) -> Result<Self::Value, ValidationFail>;
    }

    pub trait Context {
        /// Execute query against the current state of `Iroha`
        fn query(&self, query: &NumericQuery) -> Result<Value, ValidationFail>;
    }

    impl<V: TryFrom<Value>> Evaluate for EvaluatesTo<V>
    where
        V::Error: ToString,
    {
        type Value = V;

        fn evaluate(&self, context: &impl Context) -> Result<Self::Value, ValidationFail> {
            let expr = self.expression.evaluate(context)?;
            V::try_from(expr)
                .map_err(|e| InstructionExecutionError::Conversion(e.to_string()))
                .map_err(ValidationFail::InstructionFailed)
        }
    }

    impl Evaluate for Expression {
        type Value = Value;

        fn evaluate(&self, context: &impl Context) -> Result<Self::Value, ValidationFail> {
            match self {
                Expression::Raw(value) => Ok(value.clone()),
                Expression::Greater(expr) => expr.evaluate(context).map(Into::into),
                Expression::Query(expr) => expr.evaluate(context),
            }
        }
    }

    impl Evaluate for Greater {
        type Value = bool;

        fn evaluate(&self, context: &impl Context) -> Result<Self::Value, ValidationFail> {
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;
            Ok(left > right)
        }
    }

    impl Evaluate for NumericQuery {
        type Value = Value;

        fn evaluate(&self, context: &impl Context) -> Result<Self::Value, ValidationFail> {
            context.query(self)
        }
    }
}
