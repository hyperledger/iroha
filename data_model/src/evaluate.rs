//! Implementations for Expression evaluation for different expressions.

#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;

pub use self::model::*;
use crate::{
    expression::{prelude::*, Expression},
    isi::error::{BinaryOpIncompatibleNumericValueTypesError, MathError},
    prelude::*,
};

/// Expression evaluator
pub trait ExpressionEvaluator {
    /// Evaluates expression against current state of the underlying system
    ///
    /// # Errors
    ///
    /// - if expression is malformed
    fn evaluate<E: Evaluate>(&self, expression: &E) -> Result<E::Value, EvaluationError>;
}

/// Context of expression evaluation, holding (name, value) pairs for resolving identifiers.
/// Context comes into play because of [`Where`] and [`Query`] expressions.
///
/// # Example
///
/// Say you have an expression such as: `SELECT name FROM table WHERE name = "alice"`. This
/// compound expression is made up of two basic expressions, namely `SELECT FROM` and `WHERE`.
/// To evaluate any expression you have to substitute concrete values for variable names.
/// In this case, `WHERE` should be evaluated first which would place `name = "alice"`
/// inside the context. This context will then be used to evaluate `SELECT FROM`.
/// Starting expression would then be evaluated to `SELECT "alice" FROM table`
pub trait Context: Clone {
    /// Execute query against the current state of `Iroha`
    ///
    /// # Errors
    ///
    /// If query execution fails
    fn query(&self, query: &QueryBox) -> Result<Value, ValidationFail>;

    /// Return a reference to the [`Value`] corresponding to the [`Name`].
    fn get(&self, name: &Name) -> Option<&Value>;

    /// Update this context with given values.
    fn update(&mut self, other: impl IntoIterator<Item = (Name, Value)>);
}

/// Calculate the result of the expression without mutating the state.
#[allow(clippy::len_without_is_empty)] // NOTE: Evaluate cannot be empty
pub trait Evaluate {
    /// The resulting type of the expression.
    type Value;

    /// Calculate result.
    ///
    /// # Errors
    /// Concrete to each implementer.
    fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError>;
}

impl<V: TryFrom<Value>> Evaluate for EvaluatesTo<V>
where
    V::Error: ToString,
{
    type Value = V;

    fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
        let expr = self.expression.evaluate(context)?;

        V::try_from(expr).map_err(|error| EvaluationError::Conversion(error.to_string()))
    }
}

impl Evaluate for Expression {
    type Value = Value;

    fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
        macro_rules! match_evals {
            ($($non_value: ident),+ $(,)?) => {
                match self { $(
                    $non_value(expr) => expr.evaluate(context).map(Into::into)?, )+
                    Raw(value) => value.clone(),
                }
            };
        }

        use Expression::*;
        let result = match_evals!(
            // numeric
            Add,
            Subtract,
            Greater,
            Less,
            Multiply,
            Divide,
            Mod,
            RaiseTo,
            // logical
            Equal,
            Not,
            And,
            Or,
            Contains,
            ContainsAll,
            ContainsAny,
            // value
            If,
            Where,
            Query,
            ContextValue,
        );

        Ok(result)
    }
}

impl Evaluate for ContextValue {
    type Value = Value;

    fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
        context
            .get(&self.value_name)
            .cloned()
            .ok_or_else(|| EvaluationError::Find(self.value_name.to_string()))
    }
}

mod numeric {
    use super::*;

    impl Evaluate for Add {
        type Value = NumericValue;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;

            let result = match (left, right) {
                (U32(left), U32(right)) => left
                    .checked_add(right)
                    .ok_or(MathError::Overflow)
                    .map(NumericValue::from)?,
                (U128(left), U128(right)) => left
                    .checked_add(right)
                    .ok_or(MathError::Overflow)
                    .map(NumericValue::from)?,
                (Fixed(left), Fixed(right)) => left
                    .checked_add(right)
                    .map(NumericValue::from)
                    .map_err(MathError::from)?,
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }

    impl Evaluate for Subtract {
        type Value = NumericValue;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;

            let result = match (left, right) {
                (U32(left), U32(right)) => left
                    .checked_sub(right)
                    .ok_or(MathError::NotEnoughQuantity)
                    .map(NumericValue::from)?,
                (U128(left), U128(right)) => left
                    .checked_sub(right)
                    .ok_or(MathError::NotEnoughQuantity)
                    .map(NumericValue::from)?,
                (Fixed(left), Fixed(right)) => left
                    .checked_sub(right)
                    .map(NumericValue::from)
                    .map_err(MathError::from)?,
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }

    impl Evaluate for Multiply {
        type Value = NumericValue;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;

            let result = match (left, right) {
                (U32(left), U32(right)) => left
                    .checked_mul(right)
                    .ok_or(MathError::Overflow)
                    .map(NumericValue::from)?,
                (U128(left), U128(right)) => left
                    .checked_mul(right)
                    .ok_or(MathError::Overflow)
                    .map(NumericValue::from)?,
                (Fixed(left), Fixed(right)) => left
                    .checked_mul(right)
                    .map(NumericValue::from)
                    .map_err(MathError::from)?,
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }

    impl Evaluate for RaiseTo {
        type Value = NumericValue;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let value = self.left.evaluate(context)?;
            let exp = self.right.evaluate(context)?;

            let result = match (value, exp) {
                (U32(value), U32(exp)) => value
                    .checked_pow(exp)
                    .ok_or(MathError::Overflow)
                    .map(NumericValue::from)?,
                (U128(value), U32(exp)) => value
                    .checked_pow(exp)
                    .ok_or(MathError::Overflow)
                    .map(NumericValue::from)?,
                // TODO (#2945): Extend `RaiseTo` to support `Fixed`
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }

    impl Evaluate for Divide {
        type Value = NumericValue;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;

            let result = match (left, right) {
                (U32(left), U32(right)) => left
                    .checked_div(right)
                    .ok_or(MathError::DivideByZero)
                    .map(NumericValue::from)?,
                (U128(left), U128(right)) => left
                    .checked_div(right)
                    .ok_or(MathError::DivideByZero)
                    .map(NumericValue::from)?,
                (Fixed(left), Fixed(right)) => left
                    .checked_div(right)
                    .map(NumericValue::from)
                    .map_err(MathError::from)?,
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }

    impl Evaluate for Mod {
        type Value = NumericValue;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;

            let result = match (left, right) {
                (U32(left), U32(right)) => left
                    .checked_rem(right)
                    .ok_or(MathError::DivideByZero)
                    .map(NumericValue::from)?,
                (U128(left), U128(right)) => left
                    .checked_rem(right)
                    .ok_or(MathError::DivideByZero)
                    .map(NumericValue::from)?,
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }
}

mod logical {
    use super::*;

    impl Evaluate for Greater {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;

            let result = match (left, right) {
                (U32(left), U32(right)) => left > right,
                (U128(left), U128(right)) => left > right,
                (Fixed(left), Fixed(right)) => left > right,
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }

    impl Evaluate for Less {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            use NumericValue::*;
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;

            let result = match (left, right) {
                (U32(left), U32(right)) => left < right,
                (U128(left), U128(right)) => left < right,
                (Fixed(left), Fixed(right)) => left < right,
                (left, right) => Err(MathError::from(
                    BinaryOpIncompatibleNumericValueTypesError { left, right },
                ))?,
            };

            Ok(result)
        }
    }

    impl Evaluate for Equal {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;
            Ok(left == right)
        }
    }

    impl Evaluate for And {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;
            Ok(left && right)
        }
    }

    impl Evaluate for Or {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            let left = self.left.evaluate(context)?;
            let right = self.right.evaluate(context)?;
            Ok(left || right)
        }
    }

    impl Evaluate for Not {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            let expression = self.expression.evaluate(context)?;
            Ok(!expression)
        }
    }

    impl Evaluate for Contains {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            let collection = self.collection.evaluate(context)?;
            let element = self.element.evaluate(context)?;
            Ok(collection.contains(&element))
        }
    }

    impl Evaluate for ContainsAll {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            let collection = self.collection.evaluate(context)?;
            let elements = self.elements.evaluate(context)?;
            Ok(elements.iter().all(|element| collection.contains(element)))
        }
    }

    impl Evaluate for ContainsAny {
        type Value = bool;

        fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
            let collection = self.collection.evaluate(context)?;
            let elements = self.elements.evaluate(context)?;
            Ok(elements.iter().any(|element| collection.contains(element)))
        }
    }
}

impl Evaluate for If {
    type Value = Value;

    fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
        let condition = self.condition.evaluate(context)?;
        if condition {
            self.then.evaluate(context)
        } else {
            self.otherwise.evaluate(context)
        }
    }
}

impl Evaluate for Where {
    type Value = Value;

    fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
        let additional_context: Result<BTreeMap<Name, Value>, EvaluationError> = self
            .values
            .clone()
            .into_iter()
            .map(|(value_name, expression)| {
                expression
                    .evaluate(context)
                    .map(|expression_result| (value_name, expression_result))
            })
            .collect();

        let mut combined_context = context.clone();
        combined_context.update(additional_context?);
        self.expression.evaluate(&combined_context)
    }
}

impl Evaluate for QueryBox {
    type Value = Value;

    fn evaluate<C: Context>(&self, context: &C) -> Result<Self::Value, EvaluationError> {
        context
            .query(self)
            .map_err(|err| EvaluationError::Validation(Box::new(err)))
    }
}

#[model]
pub mod model {
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;

    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    use super::*;

    /// Expression evaluation error
    #[derive(
        Debug,
        displaydoc::Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Deserialize,
        Serialize,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    // TODO: Only temporarily opaque because of problems with FFI
    #[ffi_type(opaque)]
    pub enum EvaluationError {
        /// Failed due to math exception
        Math(#[cfg_attr(feature = "std", source)] MathError),
        /// Validation failed
        Validation(#[cfg_attr(feature = "std", source)] Box<ValidationFail>),
        /// `{0}`: Value not found in the context
        Find(
            #[skip_from]
            #[skip_try_from]
            String,
        ),
        /// Conversion evaluation error: {0}
        Conversion(
            #[skip_from]
            #[skip_try_from]
            String,
        ),
    }
}

pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.

    pub use super::Evaluate;
}

#[cfg(test)]
mod tests {
    use core::{fmt::Debug, str::FromStr as _};

    use iroha_crypto::KeyPair;
    use iroha_primitives::fixed::Fixed;
    use parity_scale_codec::{DecodeAll, Encode};

    use super::*;
    use crate::val_vec;

    /// Context of expression evaluation
    #[derive(Clone)]
    #[repr(transparent)]
    struct TestContext {
        values: BTreeMap<Name, Value>,
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                values: BTreeMap::new(),
            }
        }
    }

    impl super::Context for TestContext {
        fn query(&self, _: &QueryBox) -> Result<Value, ValidationFail> {
            unimplemented!("This has to be tested on iroha_core")
        }

        fn get(&self, name: &Name) -> Option<&Value> {
            self.values.get(name)
        }

        fn update(&mut self, other: impl IntoIterator<Item = (Name, Value)>) {
            self.values.extend(other)
        }
    }

    /// Example taken from [whitepaper](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/iroha_2_whitepaper.md#261-multisignature-transactions)
    #[test]
    #[allow(clippy::too_many_lines)]
    fn conditional_multisignature_quorum() -> Result<(), EvaluationError> {
        let asset_quantity_high = 750_u32.to_value();
        let asset_quantity_low = 300_u32.to_value();
        let (public_key_teller_1, _) = KeyPair::generate().expect("Valid").into();
        let (public_key_teller_2, _) = KeyPair::generate().expect("Valid").into();
        let (manager_public_key, _) = KeyPair::generate().expect("Valid").into();
        let teller_signatory_set = vec![
            Value::PublicKey(public_key_teller_1.clone()),
            Value::PublicKey(public_key_teller_2),
        ];
        let one_teller_set = Value::Vec(vec![Value::PublicKey(public_key_teller_1)]);
        let manager_signatory = Value::PublicKey(manager_public_key);
        let manager_signatory_set = Value::Vec(vec![manager_signatory.clone()]);
        let condition = If::new(
            And::new(
                Greater::new(
                    EvaluatesTo::new_unchecked(ContextValue::new(
                        Name::from_str("usd_quantity").expect("Can't fail."),
                    )),
                    500_u32,
                ),
                Less::new(
                    EvaluatesTo::new_unchecked(ContextValue::new(
                        Name::from_str("usd_quantity").expect("Can't fail."),
                    )),
                    1000_u32,
                ),
            ),
            EvaluatesTo::new_evaluates_to_value(Or::new(
                ContainsAll::new(
                    EvaluatesTo::new_unchecked(ContextValue::new(
                        Name::from_str("signatories").expect("Can't fail."),
                    )),
                    teller_signatory_set.clone(),
                ),
                Contains::new(
                    EvaluatesTo::new_unchecked(ContextValue::new(
                        Name::from_str("signatories").expect("Can't fail."),
                    )),
                    manager_signatory,
                ),
            )),
            true,
        );
        // Signed by all tellers
        let expression = Where::new(EvaluatesTo::new_evaluates_to_value(condition.clone()))
            .with_value(
                //TODO: use query to get the actual quantity of an asset from WSV
                // in that case this test should be moved to iroha_core
                Name::from_str("usd_quantity").expect("Can't fail."),
                asset_quantity_high.clone(),
            )
            .with_value(
                Name::from_str("signatories").expect("Can't fail."),
                teller_signatory_set,
            );
        assert_eq!(expression.evaluate(&TestContext::new())?, Value::Bool(true));
        // Signed by manager
        let expression = Where::new(EvaluatesTo::new_evaluates_to_value(condition.clone()))
            .with_value(
                Name::from_str("usd_quantity").expect("Can't fail."),
                asset_quantity_high.clone(),
            )
            .with_value(
                Name::from_str("signatories").expect("Can't fail."),
                manager_signatory_set,
            );
        assert_eq!(expression.evaluate(&TestContext::new())?, Value::Bool(true));
        // Signed by one teller
        let expression = Where::new(EvaluatesTo::new_evaluates_to_value(condition.clone()))
            .with_value(
                Name::from_str("usd_quantity").expect("Can't fail."),
                asset_quantity_high,
            )
            .with_value(
                Name::from_str("signatories").expect("Can't fail."),
                one_teller_set.clone(),
            );
        assert_eq!(
            expression.evaluate(&TestContext::new())?,
            Value::Bool(false)
        );
        // Signed by one teller with less value
        let expression = Where::new(EvaluatesTo::new_evaluates_to_value(condition))
            .with_value(
                Name::from_str("usd_quantity").expect("Can't fail."),
                asset_quantity_low,
            )
            .with_value(
                Name::from_str("signatories").expect("Can't fail."),
                one_teller_set,
            );
        assert_eq!(expression.evaluate(&TestContext::new())?, Value::Bool(true));
        Ok(())
    }

    #[test]
    fn where_expression() -> Result<(), EvaluationError> {
        assert_eq!(
            Where::new(EvaluatesTo::new_unchecked(ContextValue::new(
                Name::from_str("test_value").expect("Can't fail.")
            )))
            .with_value(
                Name::from_str("test_value").expect("Can't fail."),
                EvaluatesTo::new_evaluates_to_value(Add::new(2_u32, 3_u32))
            )
            .evaluate(&TestContext::new())?,
            5_u32.to_value()
        );
        Ok(())
    }

    #[test]
    fn nested_where_expression() -> Result<(), EvaluationError> {
        let expression = Where::new(EvaluatesTo::new_unchecked(ContextValue::new(
            Name::from_str("a").expect("Can't fail."),
        )))
        .with_value(Name::from_str("a").expect("Can't fail."), 2_u32);
        let outer_expression = Where::new(EvaluatesTo::new_evaluates_to_value(Add::new(
            EvaluatesTo::new_unchecked(expression),
            EvaluatesTo::new_unchecked(ContextValue::new(
                Name::from_str("b").expect("Can't fail."),
            )),
        )))
        .with_value(Name::from_str("b").expect("Can't fail."), 4_u32);
        assert_eq!(
            outer_expression.evaluate(&TestContext::new())?,
            6_u32.to_value()
        );
        Ok(())
    }

    #[test]
    fn if_condition_branches_correctly() -> Result<(), EvaluationError> {
        assert_eq!(
            If::new(true, 1_u32, 2_u32).evaluate(&TestContext::new())?,
            1_u32.to_value()
        );
        assert_eq!(
            If::new(false, 1_u32, 2_u32).evaluate(&TestContext::new())?,
            2_u32.to_value()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::unnecessary_wraps)]
    fn incorrect_types_are_caught() -> Result<(), EvaluationError> {
        fn assert_eval<I>(inst: &I, err_msg: &str)
        where
            I: Evaluate + Debug,
            I::Value: Debug,
        {
            let result: Result<_, _> = inst.evaluate(&TestContext::new());
            let _err = result.expect_err(err_msg);
        }

        assert_eval(
            &And::new(
                EvaluatesTo::new_unchecked(1_u32),
                EvaluatesTo::new_unchecked(Vec::<Value>::new()),
            ),
            "Should not be possible to apply logical and to int and vec.",
        );
        assert_eval(
            &Or::new(
                EvaluatesTo::new_unchecked(1_u32),
                EvaluatesTo::new_unchecked(Vec::<Value>::new()),
            ),
            "Should not be possible to apply logical or to int and vec.",
        );
        assert_eval(
            &Greater::new(
                EvaluatesTo::new_unchecked(1_u32),
                EvaluatesTo::new_unchecked(Vec::<Value>::new()),
            ),
            "Should not be possible to apply greater sign to int and vec.",
        );
        assert_eval(
            &Less::new(
                EvaluatesTo::new_unchecked(1_u32),
                EvaluatesTo::new_unchecked(Vec::<Value>::new()),
            ),
            "Should not be possible to apply greater sign to int and vec.",
        );
        assert_eval(
            &If::new(EvaluatesTo::new_unchecked(1_u32), 2_u32, 3_u32),
            "If condition should be bool",
        );
        assert_eval(
            &Add::new(10_u32, 1_u128),
            "Should not be possible to add `u32` and `u128`",
        );
        assert_eval(
            &Subtract::new(Fixed::try_from(10.2_f64).map_err(MathError::from)?, 1_u128),
            "Should not be possible to subtract `Fixed` and `u128`",
        );
        assert_eval(
            &Multiply::new(0_u32, Fixed::try_from(1.0_f64).map_err(MathError::from)?),
            "Should not be possible to multiply `u32` and `Fixed`",
        );
        Ok(())
    }

    #[test]
    fn operations_are_correctly_calculated() -> Result<(), EvaluationError> {
        assert_eq!(
            Add::new(1_u32, 2_u32).evaluate(&TestContext::new())?,
            3_u32.into()
        );
        assert_eq!(
            Add::new(1_u128, 2_u128).evaluate(&TestContext::new())?,
            3_u128.into(),
        );
        assert_eq!(
            Add::new(
                Fixed::try_from(1.17_f64).map_err(MathError::from)?,
                Fixed::try_from(2.13_f64).map_err(MathError::from)?
            )
            .evaluate(&TestContext::new())?,
            3.30_f64.try_into().map_err(MathError::from)?
        );
        assert_eq!(
            Subtract::new(7_u32, 2_u32).evaluate(&TestContext::new())?,
            5_u32.into()
        );
        assert_eq!(
            Subtract::new(7_u128, 2_u128).evaluate(&TestContext::new())?,
            5_u128.into()
        );
        assert_eq!(
            Subtract::new(
                Fixed::try_from(7.250_f64).map_err(MathError::from)?,
                Fixed::try_from(2.125_f64).map_err(MathError::from)?
            )
            .evaluate(&TestContext::new())?,
            5.125_f64.try_into().map_err(MathError::from)?
        );
        assert!(!Greater::new(1_u32, 2_u32).evaluate(&TestContext::new())?);
        assert!(Greater::new(2_u32, 1_u32).evaluate(&TestContext::new())?);
        assert!(Less::new(1_u32, 2_u32).evaluate(&TestContext::new())?);
        assert!(!Less::new(2_u32, 1_u32).evaluate(&TestContext::new())?);
        assert!(!Equal::new(1_u32, 2_u32).evaluate(&TestContext::new())?);
        assert!(
            Equal::new(vec![1_u32, 3_u32, 5_u32], vec![1_u32, 3_u32, 5_u32])
                .evaluate(&TestContext::new())?
        );
        assert!(Contains::new(val_vec![1_u32, 3_u32, 5_u32], 3_u32).evaluate(&TestContext::new())?);
        assert!(!Contains::new(val_vec![1_u32, 3_u32, 5_u32], 7_u32).evaluate(&TestContext::new())?);
        assert!(
            ContainsAll::new(val_vec![1_u32, 3_u32, 5_u32], val_vec![1_u32, 5_u32])
                .evaluate(&TestContext::new())?
        );
        assert!(
            !ContainsAll::new(val_vec![1_u32, 3_u32, 5_u32], val_vec![1_u32, 5_u32, 7_u32])
                .evaluate(&TestContext::new())?
        );
        Ok(())
    }

    #[test]
    #[ignore = "Stack overflow"]
    fn serde_serialization_works() {
        let expression: Expression = Add::new(1_u32, Subtract::new(7_u32, 4_u32)).into();
        let serialized_expression =
            serde_json::to_string(&expression).expect("Failed to serialize.");
        let deserialized_expression: Expression =
            serde_json::from_str(&serialized_expression).expect("Failed to de-serialize.");
        assert_eq!(
            expression
                .evaluate(&TestContext::new())
                .expect("Failed to calculate."),
            deserialized_expression
                .evaluate(&TestContext::new())
                .expect("Failed to calculate.")
        )
    }

    #[test]
    fn scale_codec_serialization_works() {
        let expression: Expression = Add::new(1_u32, Subtract::new(7_u32, 4_u32)).into();
        let serialized_expression: Vec<u8> = expression.encode();
        let deserialized_expression: Expression =
            DecodeAll::decode_all(&mut serialized_expression.as_slice())
                .expect("Failed to decode.");
        assert_eq!(
            expression
                .evaluate(&TestContext::new())
                .expect("Failed to calculate."),
            deserialized_expression
                .evaluate(&TestContext::new())
                .expect("Failed to calculate.")
        )
    }
}
