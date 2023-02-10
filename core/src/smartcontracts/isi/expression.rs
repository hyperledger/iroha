//! Implementations for Expression evaluation for different expressions.
#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]
use eyre::Result;
use iroha_data_model::{
    error::{FindError, InstructionExecutionFailure as Error, MathError},
    expression::{prelude::*, Expression},
    prelude::*,
};

use super::Evaluate;
use crate::{prelude::ValidQuery, wsv::WorldStateView};

impl<V: TryFrom<Value>> Evaluate for EvaluatesTo<V>
where
    <V as TryFrom<Value>>::Error: Into<eyre::Error>,
{
    type Value = V;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let expr = self.expression.evaluate(wsv, context)?;

        V::try_from(expr)
            .map_err(Into::into)
            .map_err(|e| Error::Conversion(e.to_string()))
    }
}

impl Evaluate for Expression {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use Expression::*;
        let eval_res = match self {
            Add(add) => add.evaluate(wsv, context)?,
            Subtract(subtract) => subtract.evaluate(wsv, context)?,
            Greater(greater) => greater.evaluate(wsv, context)?,
            Less(less) => less.evaluate(wsv, context)?,
            Equal(equal) => equal.evaluate(wsv, context)?,
            Not(not) => not.evaluate(wsv, context)?,
            And(and) => and.evaluate(wsv, context)?,
            Or(or) => or.evaluate(wsv, context)?,
            If(if_expression) => if_expression.evaluate(wsv, context)?,
            Raw(value) => *value.clone(),
            Query(query) => query.execute(wsv)?,
            Contains(contains) => contains.evaluate(wsv, context)?,
            ContainsAll(contains_all) => contains_all.evaluate(wsv, context)?,
            ContainsAny(contains_any) => contains_any.evaluate(wsv, context)?,
            Where(where_expression) => where_expression.evaluate(wsv, context)?,
            ContextValue(context_value) => context_value.evaluate(wsv, context)?,
            Multiply(multiply) => multiply.evaluate(wsv, context)?,
            Divide(divide) => divide.evaluate(wsv, context)?,
            Mod(modulus) => modulus.evaluate(wsv, context)?,
            RaiseTo(raise_to) => raise_to.evaluate(wsv, context)?,
        };
        Ok(eval_res)
    }
}

impl Evaluate for ContextValue {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        _wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        context
            .get(&self.value_name)
            .ok_or_else(|| FindError::Context(self.value_name.to_string()).into())
            .map(ToOwned::to_owned)
    }
}

impl Evaluate for Add {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        match (left, right) {
            (U32(left), U32(right)) => left
                .checked_add(right)
                .ok_or(Error::Math(MathError::Overflow))
                .map(NumericValue::from),
            (U128(left), U128(right)) => left
                .checked_add(right)
                .ok_or(Error::Math(MathError::Overflow))
                .map(NumericValue::from),
            (Fixed(left), Fixed(right)) => left
                .checked_add(right)
                .map(NumericValue::from)
                .map_err(Error::from),
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

impl Evaluate for Subtract {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        match (left, right) {
            (U32(left), U32(right)) => left
                .checked_sub(right)
                .ok_or(Error::Math(MathError::NotEnoughQuantity))
                .map(NumericValue::from),
            (U128(left), U128(right)) => left
                .checked_sub(right)
                .ok_or(Error::Math(MathError::NotEnoughQuantity))
                .map(NumericValue::from),
            (Fixed(left), Fixed(right)) => left
                .checked_sub(right)
                .map(NumericValue::from)
                .map_err(Error::from),
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

impl Evaluate for Greater {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        match (left, right) {
            (U32(left), U32(right)) => Ok(left > right),
            (U128(left), U128(right)) => Ok(left > right),
            (Fixed(left), Fixed(right)) => Ok(left > right),
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

impl Evaluate for Less {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        match (left, right) {
            (U32(left), U32(right)) => Ok(left < right),
            (U128(left), U128(right)) => Ok(left < right),
            (Fixed(left), Fixed(right)) => Ok(left < right),
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

impl Evaluate for Not {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let expression = self.expression.evaluate(wsv, context)?;
        Ok((!expression).into())
    }
}

impl Evaluate for And {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left && right).into())
    }
}

impl Evaluate for Or {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left || right).into())
    }
}

impl Evaluate for IfExpression {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let condition = self.condition.evaluate(wsv, context)?;
        if condition {
            self.then_expression.evaluate(wsv, context)
        } else {
            self.else_expression.evaluate(wsv, context)
        }
    }
}

impl Evaluate for Contains {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let collection = self.collection.evaluate(wsv, context)?;
        let element = self.element.evaluate(wsv, context)?;
        Ok(collection.contains(&element).into())
    }
}

impl Evaluate for ContainsAll {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let collection = self.collection.evaluate(wsv, context)?;
        let elements = self.elements.evaluate(wsv, context)?;
        Ok(elements
            .iter()
            .all(|element| collection.contains(element))
            .into())
    }
}

impl Evaluate for ContainsAny {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let collection = self.collection.evaluate(wsv, context)?;
        let elements = self.elements.evaluate(wsv, context)?;
        Ok(elements
            .iter()
            .any(|element| collection.contains(element))
            .into())
    }
}

impl Evaluate for Equal {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left == right).into())
    }
}

impl Evaluate for Where {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let additional_context: Result<Context, Self::Error> = self
            .values
            .clone()
            .into_iter()
            .map(|(value_name, expression)| {
                expression
                    .evaluate(wsv, context)
                    .map(|expression_result| (value_name, expression_result))
            })
            .collect();
        self.expression.evaluate(
            wsv,
            &context
                .clone()
                .into_iter()
                .chain(additional_context?.into_iter())
                .collect(),
        )
    }
}

impl Evaluate for Multiply {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        match (left, right) {
            (U32(left), U32(right)) => left
                .checked_mul(right)
                .ok_or(Error::Math(MathError::Overflow))
                .map(NumericValue::from),
            (U128(left), U128(right)) => left
                .checked_mul(right)
                .ok_or(Error::Math(MathError::Overflow))
                .map(NumericValue::from),
            (Fixed(left), Fixed(right)) => left
                .checked_mul(right)
                .map(NumericValue::from)
                .map_err(Error::from),
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

impl Evaluate for RaiseTo {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let value = self.left.evaluate(wsv, context)?;
        let exp = self.right.evaluate(wsv, context)?;
        match (value, exp) {
            (U32(value), U32(exp)) => value
                .checked_pow(exp)
                .ok_or(Error::Math(MathError::Overflow))
                .map(NumericValue::from),
            (U128(value), U32(exp)) => value
                .checked_pow(exp)
                .ok_or(Error::Math(MathError::Overflow))
                .map(NumericValue::from),
            // TODO (#2945): Extend `RaiseTo` to support `Fixed`
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

impl Evaluate for Divide {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        match (left, right) {
            (U32(left), U32(right)) => left
                .checked_div(right)
                .ok_or(Error::Math(MathError::DivideByZero))
                .map(NumericValue::from),
            (U128(left), U128(right)) => left
                .checked_div(right)
                .ok_or(Error::Math(MathError::DivideByZero))
                .map(NumericValue::from),
            (Fixed(left), Fixed(right)) => left
                .checked_div(right)
                .map(NumericValue::from)
                .map_err(Error::from),
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

impl Evaluate for Mod {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        use NumericValue::*;
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        match (left, right) {
            (U32(left), U32(right)) => left
                .checked_rem(right)
                .ok_or(Error::Math(MathError::DivideByZero))
                .map(NumericValue::from),
            (U128(left), U128(right)) => left
                .checked_rem(right)
                .ok_or(Error::Math(MathError::DivideByZero))
                .map(NumericValue::from),
            (left, right) => Err(MathError::BinaryOpIncompatibleNumericValueTypes(
                left, right,
            ))
            .map_err(Error::from),
        }
        .map(Value::from)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{fmt::Debug, str::FromStr};

    use eyre::Result;
    use iroha_crypto::KeyPair;
    use iroha_data_model::val_vec;
    use iroha_primitives::fixed::Fixed;
    use parity_scale_codec::{DecodeAll, Encode};

    use super::*;
    use crate::{kura::Kura, wsv::World};

    /// Example taken from [whitepaper](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/iroha_2_whitepaper.md#261-multisignature-transactions)
    #[test]
    #[allow(clippy::too_many_lines)]
    fn conditional_multisignature_quorum() -> Result<()> {
        let asset_quantity_high = 750_u32.to_value();
        let asset_quantity_low = 300_u32.to_value();
        let (public_key_teller_1, _) = KeyPair::generate()?.into();
        let (public_key_teller_2, _) = KeyPair::generate()?.into();
        let (manager_public_key, _) = KeyPair::generate()?.into();
        let teller_signatory_set = vec![
            Value::PublicKey(public_key_teller_1.clone()),
            Value::PublicKey(public_key_teller_2),
        ];
        let one_teller_set = Value::Vec(vec![Value::PublicKey(public_key_teller_1)]);
        let manager_signatory = Value::PublicKey(manager_public_key);
        let manager_signatory_set = Value::Vec(vec![manager_signatory.clone()]);
        let condition = IfBuilder::condition(And::new(
            Greater::new(
                EvaluatesTo::new_unchecked(
                    ContextValue::new(Name::from_str("usd_quantity").expect("Can't fail.")).into(),
                ),
                500_u32,
            ),
            Less::new(
                EvaluatesTo::new_unchecked(
                    ContextValue::new(Name::from_str("usd_quantity").expect("Can't fail.")).into(),
                ),
                1000_u32,
            ),
        ))
        .then_expression(EvaluatesTo::new_evaluates_to_value(
            Or::new(
                ContainsAll::new(
                    EvaluatesTo::new_unchecked(
                        ContextValue::new(Name::from_str("signatories").expect("Can't fail."))
                            .into(),
                    ),
                    teller_signatory_set.clone(),
                ),
                Contains::new(
                    EvaluatesTo::new_unchecked(
                        ContextValue::new(Name::from_str("signatories").expect("Can't fail."))
                            .into(),
                    ),
                    manager_signatory,
                ),
            )
            .into(),
        ))
        .else_expression(true)
        .build()
        .unwrap();
        // Signed by all tellers
        let expression = WhereBuilder::evaluate(EvaluatesTo::new_evaluates_to_value(
            condition.clone().into(),
        ))
        .with_value(
            //TODO: use query to get the actual quantity of an asset from WSV
            Name::from_str("usd_quantity").expect("Can't fail."),
            asset_quantity_high.clone(),
        )
        .with_value(
            Name::from_str("signatories").expect("Can't fail."),
            teller_signatory_set,
        )
        .build();
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by manager
        let expression = WhereBuilder::evaluate(EvaluatesTo::new_evaluates_to_value(
            condition.clone().into(),
        ))
        .with_value(
            Name::from_str("usd_quantity").expect("Can't fail."),
            asset_quantity_high.clone(),
        )
        .with_value(
            Name::from_str("signatories").expect("Can't fail."),
            manager_signatory_set,
        )
        .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by one teller
        let expression = WhereBuilder::evaluate(EvaluatesTo::new_evaluates_to_value(
            condition.clone().into(),
        ))
        .with_value(
            Name::from_str("usd_quantity").expect("Can't fail."),
            asset_quantity_high,
        )
        .with_value(
            Name::from_str("signatories").expect("Can't fail."),
            one_teller_set.clone(),
        )
        .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        // Signed by one teller with less value
        let expression =
            WhereBuilder::evaluate(EvaluatesTo::new_evaluates_to_value(condition.into()))
                .with_value(
                    Name::from_str("usd_quantity").expect("Can't fail."),
                    asset_quantity_low,
                )
                .with_value(
                    Name::from_str("signatories").expect("Can't fail."),
                    one_teller_set,
                )
                .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        Ok(())
    }

    #[test]
    fn where_expression() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        assert_eq!(
            WhereBuilder::evaluate(EvaluatesTo::new_unchecked(
                ContextValue::new(Name::from_str("test_value").expect("Can't fail.")).into()
            ))
            .with_value(
                Name::from_str("test_value").expect("Can't fail."),
                EvaluatesTo::new_evaluates_to_value(Add::new(2_u32, 3_u32).into())
            )
            .build()
            .evaluate(&WorldStateView::new(World::new(), kura), &Context::new())?,
            5_u32.to_value()
        );
        Ok(())
    }

    #[test]
    fn nested_where_expression() -> Result<()> {
        let expression = WhereBuilder::evaluate(EvaluatesTo::new_unchecked(
            ContextValue::new(Name::from_str("a").expect("Can't fail.")).into(),
        ))
        .with_value(Name::from_str("a").expect("Can't fail."), 2_u32)
        .build();
        let outer_expression: ExpressionBox =
            WhereBuilder::evaluate(EvaluatesTo::new_evaluates_to_value(
                Add::new(
                    EvaluatesTo::new_unchecked(expression.into()),
                    EvaluatesTo::new_unchecked(
                        ContextValue::new(Name::from_str("b").expect("Can't fail.")).into(),
                    ),
                )
                .into(),
            ))
            .with_value(Name::from_str("b").expect("Can't fail."), 4_u32)
            .build()
            .into();
        let kura = Kura::blank_kura_for_testing();
        assert_eq!(
            outer_expression.evaluate(&WorldStateView::new(World::new(), kura), &Context::new())?,
            6_u32.to_value()
        );
        Ok(())
    }

    #[test]
    fn if_condition_builder_builds_only_with_both_branches() {
        let _condition = IfBuilder::condition(true)
            .then_expression(1_u32)
            .build()
            .expect_err("Builder should fail if a branch is missing");
        let _condition = IfBuilder::condition(true)
            .else_expression(2_u32)
            .build()
            .expect_err("Builder should fail if a branch is missing");
        let _condition = IfBuilder::condition(true)
            .then_expression(1_u32)
            .else_expression(2_u32)
            .build()
            .expect("Builder should build if both branches are present.");
    }

    #[test]
    fn if_condition_branches_correctly() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
        assert_eq!(
            IfExpression::new(true, 1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            1_u32.to_value()
        );
        assert_eq!(
            IfExpression::new(false, 1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            2_u32.to_value()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::unnecessary_wraps)]
    fn incorrect_types_are_caught() -> Result<()> {
        fn assert_eval<I>(inst: &I, err_msg: &str)
        where
            I: Evaluate + Debug,
            I::Value: Debug,
        {
            let kura = Kura::blank_kura_for_testing();
            let wsv = WorldStateView::new(World::default(), kura);
            let result: Result<_, _> = inst.evaluate(&wsv, &Context::new());
            let _err = result.expect_err(err_msg);
        }

        assert_eval(
            &And::new(
                EvaluatesTo::new_unchecked(1_u32.into()),
                EvaluatesTo::new_unchecked(Vec::<Value>::new().into()),
            ),
            "Should not be possible to apply logical and to int and vec.",
        );
        assert_eval(
            &Or::new(
                EvaluatesTo::new_unchecked(1_u32.into()),
                EvaluatesTo::new_unchecked(Vec::<Value>::new().into()),
            ),
            "Should not be possible to apply logical or to int and vec.",
        );
        assert_eval(
            &Greater::new(
                EvaluatesTo::new_unchecked(1_u32.into()),
                EvaluatesTo::new_unchecked(Vec::<Value>::new().into()),
            ),
            "Should not be possible to apply greater sign to int and vec.",
        );
        assert_eval(
            &Less::new(
                EvaluatesTo::new_unchecked(1_u32.into()),
                EvaluatesTo::new_unchecked(Vec::<Value>::new().into()),
            ),
            "Should not be possible to apply greater sign to int and vec.",
        );
        assert_eval(
            &IfExpression::new(EvaluatesTo::new_unchecked(1_u32.into()), 2_u32, 3_u32),
            "If condition should be bool",
        );
        assert_eval(
            &Add::new(10_u32, 1_u128),
            "Should not be possible to add `u32` and `u128`",
        );
        assert_eval(
            &Subtract::new(Fixed::try_from(10.2_f64)?, 1_u128),
            "Should not be possible to subtract `Fixed` and `u128`",
        );
        assert_eval(
            &Multiply::new(0_u32, Fixed::try_from(1.0_f64)?),
            "Should not be possible to multiply `u32` and `Fixed`",
        );
        Ok(())
    }

    #[test]
    fn operations_are_correctly_calculated() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
        assert_eq!(
            Add::new(1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            3_u32.to_value()
        );
        assert_eq!(
            Add::new(1_u128, 2_u128).evaluate(&wsv, &Context::new())?,
            3_u128.to_value(),
        );
        assert_eq!(
            Add::new(Fixed::try_from(1.17_f64)?, Fixed::try_from(2.13_f64)?)
                .evaluate(&wsv, &Context::new())?,
            3.30_f64.try_to_value()?
        );
        assert_eq!(
            Subtract::new(7_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            5_u32.to_value()
        );
        assert_eq!(
            Subtract::new(7_u128, 2_u128).evaluate(&wsv, &Context::new())?,
            5_u128.to_value()
        );
        assert_eq!(
            Subtract::new(Fixed::try_from(7.250_f64)?, Fixed::try_from(2.125_f64)?)
                .evaluate(&wsv, &Context::new())?,
            5.125_f64.try_to_value()?
        );
        assert_eq!(
            Greater::new(1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Greater::new(2_u32, 1_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Less::new(1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Less::new(2_u32, 1_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Equal::new(1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Equal::new(vec![1_u32, 3_u32, 5_u32], vec![1_u32, 3_u32, 5_u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Contains::new(val_vec![1_u32, 3_u32, 5_u32], 3_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Contains::new(val_vec![1_u32, 3_u32, 5_u32], 7_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            ContainsAll::new(val_vec![1_u32, 3_u32, 5_u32], val_vec![1_u32, 5_u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            ContainsAll::new(val_vec![1_u32, 3_u32, 5_u32], val_vec![1_u32, 5_u32, 7_u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        Ok(())
    }

    #[test]
    #[ignore = "Stack overflow"]
    fn serde_serialization_works() {
        let expression: ExpressionBox = Add::new(1_u32, Subtract::new(7_u32, 4_u32)).into();
        let serialized_expression =
            serde_json::to_string(&expression).expect("Failed to serialize.");
        let deserialized_expression: ExpressionBox =
            serde_json::from_str(&serialized_expression).expect("Failed to de-serialize.");
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
        assert_eq!(
            expression
                .evaluate(&wsv, &Context::new())
                .expect("Failed to calculate."),
            deserialized_expression
                .evaluate(&wsv, &Context::new())
                .expect("Failed to calculate.")
        )
    }

    #[test]
    fn scale_codec_serialization_works() {
        let expression: ExpressionBox = Add::new(1_u32, Subtract::new(7_u32, 4_u32)).into();
        let serialized_expression: Vec<u8> = expression.encode();
        let deserialized_expression =
            ExpressionBox::decode_all(&mut serialized_expression.as_slice())
                .expect("Failed to decode.");
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(World::new(), kura);
        assert_eq!(
            expression
                .evaluate(&wsv, &Context::new())
                .expect("Failed to calculate."),
            deserialized_expression
                .evaluate(&wsv, &Context::new())
                .expect("Failed to calculate.")
        )
    }
}
