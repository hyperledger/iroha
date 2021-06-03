//! Implementations for Expression evaluation for different expressions.

use std::convert::TryFrom;

use iroha_data_model::{
    expression::{prelude::*, Expression},
    prelude::*,
};
use iroha_error::{error, Error, Result};

use super::Evaluate;
use crate::prelude::*;

impl<E: Into<Error>, V: TryFrom<Value, Error = E>> Evaluate for EvaluatesTo<V> {
    type Value = V;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        match V::try_from(self.expression.evaluate(wsv, context)?) {
            Ok(value) => Ok(value),
            Err(err) => Err(err.into()),
        }
    }
}

impl Evaluate for Expression {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        use Expression::*;
        match self {
            Add(add) => add.evaluate(wsv, context),
            Subtract(subtract) => subtract.evaluate(wsv, context),
            Greater(greater) => greater.evaluate(wsv, context),
            Less(less) => less.evaluate(wsv, context),
            Equal(equal) => equal.evaluate(wsv, context),
            Not(not) => not.evaluate(wsv, context),
            And(and) => and.evaluate(wsv, context),
            Or(or) => or.evaluate(wsv, context),
            If(if_expression) => if_expression.evaluate(wsv, context),
            Raw(value) => Ok(*value.clone()),
            Query(query) => query.execute(wsv),
            Contains(contains) => contains.evaluate(wsv, context),
            ContainsAll(contains_all) => contains_all.evaluate(wsv, context),
            ContainsAny(contains_any) => contains_any.evaluate(wsv, context),
            Where(where_expression) => where_expression.evaluate(wsv, context),
            ContextValue(context_value) => context_value.evaluate(wsv, context),
            Multiply(multiply) => multiply.evaluate(wsv, context),
            Divide(divide) => divide.evaluate(wsv, context),
            Mod(modulus) => modulus.evaluate(wsv, context),
            RaiseTo(raise_to) => raise_to.evaluate(wsv, context),
        }
    }
}

impl Evaluate for ContextValue {
    type Value = Value;

    fn evaluate(&self, _wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        context
            .get(&self.value_name)
            .ok_or_else(|| error!("Value with name {} not found in context", self.value_name))
            .map(ToOwned::to_owned)
    }
}

impl Evaluate for Add {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left + right).into())
    }
}

impl Evaluate for Subtract {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left - right).into())
    }
}

impl Evaluate for Greater {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left > right).into())
    }
}

impl Evaluate for Less {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left < right).into())
    }
}

impl Evaluate for Not {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let expression = self.expression.evaluate(wsv, context)?;
        Ok((!expression).into())
    }
}

impl Evaluate for And {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left && right).into())
    }
}

impl Evaluate for Or {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left || right).into())
    }
}

impl Evaluate for IfExpression {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
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

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let collection = self.collection.evaluate(wsv, context)?;
        let element = self.element.evaluate(wsv, context)?;
        Ok(collection.contains(&element).into())
    }
}

impl Evaluate for ContainsAll {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let collection = self.collection.evaluate(wsv, context)?;
        let elements = self.elements.evaluate(wsv, context)?;
        Ok(elements
            .iter()
            .all(|element| collection.contains(element))
            .into())
    }
}

impl Evaluate for ContainsAny {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let collection = self.collection.evaluate(wsv, context)?;
        let elements = self.elements.evaluate(wsv, context)?;
        Ok(elements
            .iter()
            .any(|element| collection.contains(element))
            .into())
    }
}

impl Evaluate for Equal {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left == right).into())
    }
}

impl Evaluate for Where {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let additional_context: Result<Context> = self
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

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left * right).into())
    }
}

impl Evaluate for RaiseTo {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok(left.pow(right).into())
    }
}

impl Evaluate for Divide {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        #[allow(clippy::integer_division)]
        if right == 0 {
            Err(error!("Failed to divide by zero"))
        } else {
            Ok((left / right).into())
        }
    }
}

impl Evaluate for Mod {
    type Value = Value;

    fn evaluate(&self, wsv: &WorldStateView, context: &Context) -> Result<Self::Value> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left % right).into())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{error::Error as StdError, fmt::Debug};

    use iroha_crypto::KeyPair;
    use iroha_error::Result;
    use iroha_macro::error::ErrorTryFromEnum;
    use parity_scale_codec::{Decode, Encode};

    use super::*;

    /// Example taken from [whitepaper](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/iroha_2_whitepaper.md#261-multisignature-transactions)
    #[test]
    fn conditional_multisignature_quorum() -> Result<()> {
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
            Greater::new(ContextValue::new("usd_quantity"), 500_u32),
            Less::new(ContextValue::new("usd_quantity"), 1000_u32),
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
                "usd_quantity".to_owned(),
                asset_quantity_high.clone(),
            )
            .with_value("signatories".to_owned(), teller_signatory_set)
            .build();
        let wsv = WorldStateView::new(World::new());
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by manager
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_owned(), asset_quantity_high.clone())
            .with_value("signatories".to_owned(), manager_signatory_set)
            .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by one teller
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_owned(), asset_quantity_high)
            .with_value("signatories".to_owned(), one_teller_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        // Signed by one teller with less value
        let expression = WhereBuilder::evaluate(condition)
            .with_value("usd_quantity".to_owned(), asset_quantity_low)
            .with_value("signatories".to_owned(), one_teller_set)
            .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        Ok(())
    }

    #[test]
    fn where_expression() -> Result<()> {
        assert_eq!(
            WhereBuilder::evaluate(ContextValue::new("test_value"))
                .with_value("test_value".to_owned(), Add::new(2_u32, 3_u32))
                .build()
                .evaluate(&WorldStateView::new(World::new()), &Context::new())?,
            Value::U32(5)
        );
        Ok(())
    }

    #[test]
    fn nested_where_expression() -> Result<()> {
        let expression = WhereBuilder::evaluate(ContextValue::new("a"))
            .with_value("a".to_owned(), 2_u32)
            .build();
        let outer_expression: ExpressionBox =
            WhereBuilder::evaluate(Add::new(expression, ContextValue::new("b")))
                .with_value("b".to_owned(), 4_u32)
                .build()
                .into();
        assert_eq!(
            outer_expression.evaluate(&WorldStateView::new(World::new()), &Context::new())?,
            Value::U32(6)
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
        let wsv = WorldStateView::new(World::new());
        assert_eq!(
            IfExpression::new(true, 1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            Value::U32(1)
        );
        assert_eq!(
            IfExpression::new(false, 1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            Value::U32(2)
        );
        Ok(())
    }

    #[test]
    fn wrong_operand_types_are_caught() {
        fn assert_eval<I, E>(inst: &I, err_msg: &str)
        where
            I: Evaluate + Debug,
            I::Value: Debug,
            E: StdError + Eq + Default + 'static,
        {
            let wsv = WorldStateView::new(World::new());
            let result: Result<_> = inst.evaluate(&wsv, &Context::new());
            let err = result.expect_err(err_msg);
            let err = err.downcast_ref::<E>().unwrap();
            assert_eq!(err, &E::default());
        }

        assert_eval::<_, ErrorTryFromEnum<Value, u32>>(
            &Add::new(10_u32, true),
            "Should not be possible to add int and bool.",
        );
        assert_eval::<_, ErrorTryFromEnum<Value, u32>>(
            &Subtract::new(10_u32, true),
            "Should not be possible to subtract int and bool.",
        );
        assert_eval::<_, ErrorTryFromEnum<Value, bool>>(
            &And::new(1_u32, Vec::<Value>::new()),
            "Should not be possible to apply logical and to int and vec.",
        );
        assert_eval::<_, ErrorTryFromEnum<Value, bool>>(
            &Or::new(1_u32, Vec::<Value>::new()),
            "Should not be possible to apply logical or to int and vec.",
        );
        assert_eval::<_, ErrorTryFromEnum<Value, u32>>(
            &Greater::new(1_u32, Vec::<Value>::new()),
            "Should not be possible to apply greater sign to int and vec.",
        );
        assert_eval::<_, ErrorTryFromEnum<Value, u32>>(
            &Less::new(1_u32, Vec::<Value>::new()),
            "Should not be possible to apply greater sign to int and vec.",
        );
        assert_eval::<_, ErrorTryFromEnum<Value, bool>>(
            &IfExpression::new(1_u32, 2_u32, 3_u32),
            "If condition should be bool",
        );
    }

    #[test]
    fn operations_are_correctly_calculated() -> Result<()> {
        let wsv = WorldStateView::new(World::new());
        assert_eq!(
            Add::new(1_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            Value::U32(3)
        );
        assert_eq!(
            Subtract::new(7_u32, 2_u32).evaluate(&wsv, &Context::new())?,
            Value::U32(5)
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
            Contains::new(vec![1_u32, 3_u32, 5_u32], 3_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Contains::new(vec![1_u32, 3_u32, 5_u32], 7_u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            ContainsAll::new(vec![1_u32, 3_u32, 5_u32], vec![1_u32, 5_u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            ContainsAll::new(vec![1_u32, 3_u32, 5_u32], vec![1_u32, 5_u32, 7_u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        Ok(())
    }

    #[test]
    fn serde_serialization_works() {
        let expression: ExpressionBox = Add::new(1_u32, Subtract::new(7_u32, 4_u32)).into();
        let serialized_expression =
            serde_json::to_string(&expression).expect("Failed to serialize.");
        let deserialized_expression: ExpressionBox =
            serde_json::from_str(&serialized_expression).expect("Failed to deserialize.");
        let wsv = WorldStateView::new(World::new());
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
        let deserialized_expression = ExpressionBox::decode(&mut serialized_expression.as_slice())
            .expect("Failed to decode.");
        let wsv = WorldStateView::new(World::new());
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
