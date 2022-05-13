//! Implementations for Expression evaluation for different expressions.

use eyre::Result;
use iroha_data_model::{
    expression::{prelude::*, Expression},
    prelude::*,
};

use super::{Error, Evaluate, FindError, MathError};
use crate::{
    prelude::ValidQuery,
    wsv::{WorldStateView, WorldTrait},
};

impl<V: TryFrom<Value>, W: WorldTrait> Evaluate<W> for EvaluatesTo<V>
where
    <V as TryFrom<Value>>::Error: Into<eyre::Error>,
{
    type Value = V;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let expr = self.expression.evaluate(wsv, context)?;

        V::try_from(expr)
            .map_err(Into::into)
            .map_err(|e| Error::Conversion(e.to_string()))
    }
}

impl<W: WorldTrait> Evaluate<W> for Expression {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
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

impl<W: WorldTrait> Evaluate<W> for ContextValue {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        _wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        context
            .get(&self.value_name)
            .ok_or_else(|| Error::Find(Box::new(FindError::Context(self.value_name.clone()))))
            .map(ToOwned::to_owned)
    }
}

impl<W: WorldTrait> Evaluate<W> for Add {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left + right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for Subtract {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left - right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for Greater {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left > right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for Less {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left < right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for Not {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let expression = self.expression.evaluate(wsv, context)?;
        Ok((!expression).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for And {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left && right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for Or {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left || right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for IfExpression {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
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

impl<W: WorldTrait> Evaluate<W> for Contains {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let collection = self.collection.evaluate(wsv, context)?;
        let element = self.element.evaluate(wsv, context)?;
        Ok(collection.contains(&element).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for ContainsAll {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
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

impl<W: WorldTrait> Evaluate<W> for ContainsAny {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
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

impl<W: WorldTrait> Evaluate<W> for Equal {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left == right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for Where {
    type Error = Error;
    type Value = Value;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
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

impl<W: WorldTrait> Evaluate<W> for Multiply {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left * right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for RaiseTo {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok(left.pow(right).into())
    }
}

impl<W: WorldTrait> Evaluate<W> for Divide {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left: u32 = self.left.evaluate(wsv, context)?;
        let right: u32 = self.right.evaluate(wsv, context)?;
        left.checked_div(right)
            .map(Value::U32)
            .ok_or(Error::Math(MathError::DivideByZero))
    }
}

impl<W: WorldTrait> Evaluate<W> for Mod {
    type Value = Value;
    type Error = Error;

    fn evaluate(
        &self,
        wsv: &WorldStateView<W>,
        context: &Context,
    ) -> Result<Self::Value, Self::Error> {
        let left = self.left.evaluate(wsv, context)?;
        let right = self.right.evaluate(wsv, context)?;
        Ok((left % right).into())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::{error::Error as StdError, fmt::Debug};

    use eyre::Result;
    use iroha_crypto::KeyPair;
    use iroha_macro::error::ErrorTryFromEnum;
    use parity_scale_codec::{Decode, Encode};

    use super::*;
    use crate::wsv::World;

    /// Example taken from [whitepaper](https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/iroha_2_whitepaper.md#261-multisignature-transactions)
    #[test]
    fn conditional_multisignature_quorum() -> Result<()> {
        let asset_quantity_high = Value::U32(750);
        let asset_quantity_low = Value::U32(300);
        let (public_key_teller_1, _) = KeyPair::generate()?.into();
        let (public_key_teller_2, _) = KeyPair::generate()?.into();
        let (manager_public_key, _) = KeyPair::generate()?.into();
        let teller_signatory_set = Value::Vec(vec![
            Value::PublicKey(public_key_teller_1.clone()),
            Value::PublicKey(public_key_teller_2),
        ]);
        let one_teller_set = Value::Vec(vec![Value::PublicKey(public_key_teller_1)]);
        let manager_signatory = Value::PublicKey(manager_public_key);
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
        .build()
        .unwrap()
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
        let wsv = WorldStateView::<World>::new(World::new());
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
                .evaluate(&WorldStateView::<World>::new(World::new()), &Context::new())?,
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
            outer_expression
                .evaluate(&WorldStateView::<World>::new(World::new()), &Context::new())?,
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
        let wsv = WorldStateView::<World>::new(World::new());
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
    #[allow(clippy::unnecessary_wraps)]
    fn incorrect_types_are_caught() -> Result<()> {
        fn assert_eval<I, E>(inst: &I, err_msg: &str)
        where
            I: Evaluate<World> + Debug,
            I::Value: Debug,
            E: StdError + Eq + Default + Send + Sync + 'static,
        {
            let wsv = WorldStateView::new(World::default());
            let result: Result<_, _> = inst.evaluate(&wsv, &Context::new());
            let _err = result.expect_err(err_msg);
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
        Ok(())
    }

    #[test]
    fn operations_are_correctly_calculated() -> Result<()> {
        let wsv = WorldStateView::<World>::new(World::new());
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
            serde_json::from_str(&serialized_expression).expect("Failed to de-serialize.");
        let wsv = WorldStateView::<World>::new(World::new());
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
        let wsv = WorldStateView::<World>::new(World::new());
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
