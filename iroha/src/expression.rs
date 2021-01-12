//! Implementations for Expression evaluation for different expressions.

use crate::prelude::*;
use iroha_data_model::{
    expression::{prelude::*, Expression},
    prelude::*,
};
use std::{convert::TryFrom, string::ToString};

/// Calculate the result of the expression without mutating the state.
pub trait Evaluate {
    /// The resulting type of the expression.
    type Value;

    /// Calculates result.
    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String>;
}

impl<E: ToString, V: TryFrom<Value, Error = E>> Evaluate for EvaluatesTo<V> {
    type Value = V;

    fn evaluate(
        &self,
        world_state_view: &WorldStateView,
        context: &Context,
    ) -> Result<Self::Value, String> {
        V::try_from(self.expression.evaluate(world_state_view, context)?).map_err(|e| e.to_string())
    }
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
            Expression::Query(query) => query.execute(world_state_view),
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

impl Evaluate for IfExpression {
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

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use parity_scale_codec::{Decode, Encode};

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
            Greater::new(ContextValue::new("usd_quantity"), 500u32),
            Less::new(ContextValue::new("usd_quantity"), 1000u32),
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
        let wsv = WorldStateView::new(World::new());
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by manager
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_string(), asset_quantity_high.clone())
            .with_value("signatories".to_string(), manager_signatory_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        // Signed by one teller
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_string(), asset_quantity_high.clone())
            .with_value("signatories".to_string(), one_teller_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        // Signed by one teller with less value
        let expression = WhereBuilder::evaluate(condition.clone())
            .with_value("usd_quantity".to_string(), asset_quantity_low.clone())
            .with_value("signatories".to_string(), one_teller_set.clone())
            .build();
        assert_eq!(
            expression.evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        Ok(())
    }

    #[test]
    fn where_expression() -> Result<(), String> {
        assert_eq!(
            WhereBuilder::evaluate(ContextValue::new("test_value"))
                .with_value("test_value".to_string(), Add::new(2u32, 3u32))
                .build()
                .evaluate(&WorldStateView::new(World::new()), &Context::new())?,
            Value::U32(5)
        );
        Ok(())
    }

    #[test]
    fn nested_where_expression() -> Result<(), String> {
        let expression = WhereBuilder::evaluate(ContextValue::new("a"))
            .with_value("a".to_string(), 2u32)
            .build();
        let outer_expression: ExpressionBox =
            WhereBuilder::evaluate(Add::new(expression, ContextValue::new("b")))
                .with_value("b".to_string(), 4u32)
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
        let _ = IfBuilder::condition(true)
            .then_expression(1u32)
            .build()
            .expect_err("Builder should fail if a branch is missing");
        let _ = IfBuilder::condition(true)
            .else_expression(2u32)
            .build()
            .expect_err("Builder should fail if a branch is missing");
        let _ = IfBuilder::condition(true)
            .then_expression(1u32)
            .else_expression(2u32)
            .build()
            .expect("Builder should build if both branches are present.");
    }

    #[test]
    fn if_condition_branches_correctly() -> Result<(), String> {
        let wsv = WorldStateView::new(World::new());
        assert_eq!(
            IfExpression::new(true, 1u32, 2u32).evaluate(&wsv, &Context::new())?,
            Value::U32(1)
        );
        assert_eq!(
            IfExpression::new(false, 1u32, 2u32).evaluate(&wsv, &Context::new())?,
            Value::U32(2)
        );
        Ok(())
    }

    #[test]
    fn wrong_operand_types_are_caught() {
        let wsv = WorldStateView::new(World::new());
        assert!(Add::new(10u32, true)
            .evaluate(&wsv, &Context::new())
            .expect_err("Should not be possible to add int and bool.")
            .ends_with("is not U32."));
        assert!(Subtract::new(10u32, true)
            .evaluate(&wsv, &Context::new())
            .expect_err("Should not be possible to subtract int and bool.")
            .ends_with("is not U32."));
        assert!(And::new(1u32, Vec::<Value>::new())
            .evaluate(&wsv, &Context::new())
            .expect_err("Should not be possible to apply logical and to int and vec.")
            .ends_with("is not bool."));
        assert!(Or::new(1u32, Vec::<Value>::new())
            .evaluate(&wsv, &Context::new())
            .expect_err("Should not be possible to apply logical or to int and vec.")
            .ends_with("is not bool."));
        assert!(Greater::new(1u32, Vec::<Value>::new())
            .evaluate(&wsv, &Context::new())
            .expect_err("Should not be possible to apply greater sign to int and vec.")
            .ends_with("is not U32."));
        assert!(Less::new(1u32, Vec::<Value>::new())
            .evaluate(&wsv, &Context::new())
            .expect_err("Should not be possible to apply greater sign to int and vec.")
            .ends_with("is not U32."));
        assert!(IfExpression::new(1u32, 2u32, 3u32)
            .evaluate(&wsv, &Context::new())
            .expect_err("If condition should be bool")
            .ends_with("is not bool."));
    }

    #[test]
    fn operations_are_correctly_calculated() -> Result<(), String> {
        let wsv = WorldStateView::new(World::new());
        assert_eq!(
            Add::new(1u32, 2u32).evaluate(&wsv, &Context::new())?,
            Value::U32(3)
        );
        assert_eq!(
            Subtract::new(7u32, 2u32).evaluate(&wsv, &Context::new())?,
            Value::U32(5)
        );
        assert_eq!(
            Greater::new(1u32, 2u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Greater::new(2u32, 1u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Less::new(1u32, 2u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Less::new(2u32, 1u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Equal::new(1u32, 2u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            Equal::new(vec![1u32, 3u32, 5u32], vec![1u32, 3u32, 5u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Contains::new(vec![1u32, 3u32, 5u32], 3u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            Contains::new(vec![1u32, 3u32, 5u32], 7u32).evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        assert_eq!(
            ContainsAll::new(vec![1u32, 3u32, 5u32], vec![1u32, 5u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(true)
        );
        assert_eq!(
            ContainsAll::new(vec![1u32, 3u32, 5u32], vec![1u32, 5u32, 7u32])
                .evaluate(&wsv, &Context::new())?,
            Value::Bool(false)
        );
        Ok(())
    }

    #[test]
    fn serde_serialization_works() {
        let expression: ExpressionBox = Add::new(1u32, Subtract::new(7u32, 4u32)).into();
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
        let expression: ExpressionBox = Add::new(1u32, Subtract::new(7u32, 4u32)).into();
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
