//! Instruction validation module

use alloc::borrow::ToOwned as _;

use super::*;

mod account;
mod asset;
mod asset_definition;
mod domain;
mod parameter;
mod peer;
mod permission_token;
mod permission_token_definition;
mod role;
mod trigger;
mod validator;

macro_rules! evaluate_field {
    ($authority:ident, $validate_query:ident, <$isi:ident as $isi_type:ty>::$field:ident) => {{
        fn type_check(_isi: &$isi_type) {}
        type_check($isi);

        let verdict =
            validate_query_in_expression($authority, $validate_query, $isi.$field().expression());
        if verdict.is_deny() {
            return verdict;
        }

        $isi.$field().evaluate(&Context::new()).dbg_expect(concat!(
            "Failed to evaluate `",
            stringify!($field),
            "` of `",
            stringify!($isi_type),
            "`"
        ))
    }};
}

macro_rules! deny_unsupported_instruction {
    ($isi_type:ty) => {
        deny!(concat!("Unsupported `", stringify!($isi_type), "` instruction").to_owned())
    };
}

macro_rules! typeless_match {
    ($matching:ident {
        $($variant:path)|+ as $ident:ident => {$expr:expr}
        $($other_pat:pat => $other_expr:expr),* $(,)?
    }) => {
        match $matching {
            $(
                $variant($ident) => {$expr}
            )+
            $($other_pat => $other_expr),*
        }
    };
    // Form for complex cases
    ($matching:tt {
        $($variant:tt)|+ => {$expr:expr}
        $($other_pat:pat => $other_expr:expr),* $(,)?
    }) => {
        match $matching {
            $(
                $variant => {$expr}
            )+
            $($other_pat => $other_expr),*
        }
    };
}

impl DefaultValidate for InstructionBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        use InstructionBox::*;

        typeless_match!(self {
            Register
            | Unregister
            | Mint
            | Burn
            | Transfer
            | If
            | Pair
            | Sequence
            | Fail
            | SetKeyValue
            | RemoveKeyValue
            | Grant
            | Revoke
            | ExecuteTrigger
            | SetParameter
            | NewParameter
            | Upgrade as internal => {
                internal.default_validate(authority, validate_query)
            }
        })
    }
}

impl DefaultValidate for RegisterBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let object = evaluate_field!(authority, validate_query, <self as RegisterBox>::object);

        match object {
            RegistrableBox::Peer(object) => {
                Register::<Peer>::new(*object).default_validate(authority, validate_query)
            }
            RegistrableBox::Domain(object) => {
                Register::<Domain>::new(*object).default_validate(authority, validate_query)
            }
            RegistrableBox::Account(object) => {
                Register::<Account>::new(*object).default_validate(authority, validate_query)
            }
            RegistrableBox::AssetDefinition(object) => Register::<AssetDefinition>::new(*object)
                .default_validate(authority, validate_query),
            RegistrableBox::Asset(object) => {
                Register::<Asset>::new(*object).default_validate(authority, validate_query)
            }
            RegistrableBox::Trigger(object) => {
                Register::<Trigger<FilterBox, Executable>>::new(*object)
                    .default_validate(authority, validate_query)
            }
            RegistrableBox::Role(object) => {
                Register::<Role>::new(*object).default_validate(authority, validate_query)
            }
            RegistrableBox::PermissionTokenDefinition(object) => {
                Register::<PermissionTokenDefinition>::new(*object)
                    .default_validate(authority, validate_query)
            }
        }
    }
}

impl DefaultValidate for UnregisterBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        use IdBox::*;

        let object_id = evaluate_field!(
            authority,
            validate_query,
            <self as UnregisterBox>::object_id
        );

        match object_id {
            AccountId(object_id) => {
                Unregister::<Account>::new(object_id).default_validate(authority, validate_query)
            }
            AssetId(object_id) => {
                Unregister::<Asset>::new(object_id).default_validate(authority, validate_query)
            }
            AssetDefinitionId(object_id) => Unregister::<AssetDefinition>::new(object_id)
                .default_validate(authority, validate_query),
            DomainId(object_id) => {
                Unregister::<Domain>::new(object_id).default_validate(authority, validate_query)
            }
            PeerId(object_id) => {
                Unregister::<Peer>::new(object_id).default_validate(authority, validate_query)
            }
            PermissionTokenDefinitionId(object_id) => {
                Unregister::<PermissionTokenDefinition>::new(object_id)
                    .default_validate(authority, validate_query)
            }
            RoleId(object_id) => {
                Unregister::<Role>::new(object_id).default_validate(authority, validate_query)
            }
            TriggerId(object_id) => Unregister::<Trigger<FilterBox, Executable>>::new(object_id)
                .default_validate(authority, validate_query),
            ParameterId(_) => deny_unsupported_instruction!(Unregister),
        }
    }
}

impl DefaultValidate for MintBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let destination_id =
            evaluate_field!(authority, validate_query, <self as MintBox>::destination_id);
        let object = evaluate_field!(authority, validate_query, <self as MintBox>::object);

        typeless_match!((destination_id, object) {
            (IdBox::AssetId(id), Value::Numeric(NumericValue::U128(object)))
            | (IdBox::AssetId(id), Value::Numeric(NumericValue::Fixed(object)))
            | (IdBox::AccountId(id), Value::PublicKey(object))
            | (IdBox::AccountId(id), Value::SignatureCheckCondition(object)) => {
                Mint::new(object, id).default_validate(authority, validate_query)
            }
            (IdBox::AssetId(id), Value::Numeric(NumericValue::U32(object))) =>
                Mint::<Asset, _>::new(object, id).default_validate(authority, validate_query),
            (IdBox::TriggerId(id), Value::Numeric(NumericValue::U32(object))) =>
                Mint::<Trigger<FilterBox, Executable>, _>::new(object, id).default_validate(authority, validate_query),
            _ => deny_unsupported_instruction!(Mint),
        })
    }
}

impl DefaultValidate for BurnBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let destination_id =
            evaluate_field!(authority, validate_query, <self as BurnBox>::destination_id);
        let object = evaluate_field!(authority, validate_query, <self as BurnBox>::object);

        typeless_match!((destination_id, object) {
            (IdBox::AssetId(id), Value::Numeric(NumericValue::U32(value)))
            | (IdBox::AssetId(id), Value::Numeric(NumericValue::U128(value)))
            | (IdBox::AssetId(id), Value::Numeric(NumericValue::Fixed(value)))
            | (IdBox::AccountId(id), Value::PublicKey(value)) => {
                Burn::new(value, id).default_validate(authority, validate_query)
            }
            _ => deny_unsupported_instruction!(Burn),
        })
    }
}

impl DefaultValidate for TransferBox {
    #[allow(unused_parens)] // Need to be able to use complex form of `typeless_match!`
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let object = evaluate_field!(authority, validate_query, <self as TransferBox>::object);

        let (IdBox::AssetId(source_asset_id), IdBox::AccountId(destination_account_id)) = (
            evaluate_field!(authority, validate_query, <self as TransferBox>::source_id),
            evaluate_field!(authority, validate_query, <self as TransferBox>::destination_id),
        ) else {
            deny_unsupported_instruction!(Transfer)
        };

        typeless_match!((object) {
            (Value::Numeric(NumericValue::U32(quantity)))
            | (Value::Numeric(NumericValue::U128(quantity)))
            | (Value::Numeric(NumericValue::Fixed(quantity))) => {
                Transfer::new(source_asset_id, quantity, destination_account_id).default_validate(authority, validate_query)
            }
            _ => deny_unsupported_instruction!(Transfer)
        })
    }
}

impl DefaultValidate for SetKeyValueBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        use IdBox::*;

        let object_id = evaluate_field!(
            authority,
            validate_query,
            <self as SetKeyValueBox>::object_id
        );
        let key = evaluate_field!(authority, validate_query, <self as SetKeyValueBox>::key);
        let value = evaluate_field!(authority, validate_query, <self as SetKeyValueBox>::value);

        match object_id {
            AssetId(id) => SetKeyValue::<Asset, _, _>::new(id, key, value)
                .default_validate(authority, validate_query),
            AssetDefinitionId(id) => SetKeyValue::<AssetDefinition, _, _>::new(id, key, value)
                .default_validate(authority, validate_query),
            AccountId(id) => SetKeyValue::<Account, _, _>::new(id, key, value)
                .default_validate(authority, validate_query),
            DomainId(id) => SetKeyValue::<Domain, _, _>::new(id, key, value)
                .default_validate(authority, validate_query),
            _ => deny_unsupported_instruction!(SetKeyValue),
        }
    }
}

impl DefaultValidate for RemoveKeyValueBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        use IdBox::*;

        let object_id = evaluate_field!(
            authority,
            validate_query,
            <self as RemoveKeyValueBox>::object_id
        );
        let key = evaluate_field!(authority, validate_query, <self as RemoveKeyValueBox>::key);

        match object_id {
            AssetId(id) => {
                RemoveKeyValue::<Asset, _>::new(id, key).default_validate(authority, validate_query)
            }
            AssetDefinitionId(id) => RemoveKeyValue::<AssetDefinition, _>::new(id, key)
                .default_validate(authority, validate_query),
            AccountId(id) => RemoveKeyValue::<Account, _>::new(id, key)
                .default_validate(authority, validate_query),
            DomainId(id) => RemoveKeyValue::<Domain, _>::new(id, key)
                .default_validate(authority, validate_query),
            _ => deny_unsupported_instruction!(SetKeyValue),
        }
    }
}

impl DefaultValidate for FailBox {
    fn default_validate<Q>(
        &self,
        _authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass!()
    }
}

impl DefaultValidate for GrantBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let destination_id = evaluate_field!(
            authority,
            validate_query,
            <self as GrantBox>::destination_id
        );
        let object = evaluate_field!(authority, validate_query, <self as GrantBox>::object);

        typeless_match!((destination_id, object) {
            (IdBox::AccountId(account_id), Value::PermissionToken(token_or_role))
            | (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(token_or_role))) => {
                Grant::new(token_or_role, account_id).default_validate(authority, validate_query)
            }
            _ => deny_unsupported_instruction!(Grant),
        })
    }
}

impl DefaultValidate for RevokeBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let destination_id = evaluate_field!(
            authority,
            validate_query,
            <self as RevokeBox>::destination_id
        );
        let object = evaluate_field!(authority, validate_query, <self as RevokeBox>::object);

        typeless_match!((destination_id, object) {
            (IdBox::AccountId(account_id), Value::PermissionToken(token_or_role))
            | (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(token_or_role))) => {
                Revoke::new(token_or_role, account_id).default_validate(authority, validate_query)
            }
            _ => deny_unsupported_instruction!(Revoke),
        })
    }
}

impl DefaultValidate for SetParameterBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let parameter = evaluate_field!(
            authority,
            validate_query,
            <self as SetParameterBox>::parameter
        );
        SetParameter::new(parameter).default_validate(authority, validate_query)
    }
}

impl DefaultValidate for NewParameterBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let parameter = evaluate_field!(
            authority,
            validate_query,
            <self as NewParameterBox>::parameter
        );
        NewParameter::new(parameter).default_validate(authority, validate_query)
    }
}

impl DefaultValidate for ExecuteTriggerBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let trigger_id = evaluate_field!(
            authority,
            validate_query,
            <self as ExecuteTriggerBox>::trigger_id
        );
        trigger::validate_execution(trigger_id, authority)
    }
}

impl DefaultValidate for UpgradeBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let object = evaluate_field!(authority, validate_query, <self as UpgradeBox>::object);
        match object {
            UpgradableBox::Validator(validator) => {
                Upgrade::new(validator).default_validate(authority, validate_query)
            }
        }
    }
}

impl DefaultValidate for Conditional {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let condition =
            evaluate_field!(authority, validate_query, <self as Conditional>::condition);
        if condition {
            return self.then().default_validate(authority, validate_query);
        }
        if let Some(otherwise) = self.otherwise() {
            otherwise.default_validate(authority, validate_query)
        } else {
            pass!()
        }
    }
}

impl DefaultValidate for Pair {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        self.left_instruction()
            .default_validate(authority, validate_query)
            .and_then(|| {
                self.right_instruction()
                    .default_validate(authority, validate_query)
            })
    }
}

impl DefaultValidate for SequenceBox {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        for instruction in self.instructions() {
            let verdict = instruction.default_validate(authority, validate_query);
            if verdict.is_deny() {
                return verdict;
            }
        }

        pass!()
    }
}

fn validate_query_in_expression<Q>(
    authority: &<Account as Identifiable>::Id,
    validate_query: Q,
    expression: &Expression,
) -> Verdict
where
    Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
{
    let validate_query_in_expression_curry =
        |expression| validate_query_in_expression(authority, validate_query, expression);

    macro_rules! validate_binary_expression {
        ($e:ident) => {
            validate_query_in_expression_curry($e.left().expression())
                .and_then(|| validate_query_in_expression_curry($e.right().expression()))
        };
    }

    match expression {
        Expression::Add(expression) => validate_binary_expression!(expression),
        Expression::Subtract(expression) => validate_binary_expression!(expression),
        Expression::Multiply(expression) => validate_binary_expression!(expression),
        Expression::Divide(expression) => validate_binary_expression!(expression),
        Expression::Mod(expression) => validate_binary_expression!(expression),
        Expression::RaiseTo(expression) => validate_binary_expression!(expression),
        Expression::Greater(expression) => validate_binary_expression!(expression),
        Expression::Less(expression) => validate_binary_expression!(expression),
        Expression::Equal(expression) => validate_binary_expression!(expression),
        Expression::Not(expression) => {
            validate_query_in_expression_curry(expression.expression().expression())
        }
        Expression::And(expression) => validate_binary_expression!(expression),
        Expression::Or(expression) => validate_binary_expression!(expression),
        Expression::If(expression) => {
            validate_query_in_expression_curry(expression.condition().expression())
                .and_then(|| validate_query_in_expression_curry(expression.then().expression()))
                .and_then(|| {
                    validate_query_in_expression_curry(expression.otherwise().expression())
                })
        }
        Expression::Contains(expression) => {
            validate_query_in_expression_curry(expression.collection().expression())
                .and_then(|| validate_query_in_expression_curry(expression.element().expression()))
        }
        Expression::ContainsAll(expression) => {
            validate_query_in_expression_curry(expression.collection().expression())
                .and_then(|| validate_query_in_expression_curry(expression.elements().expression()))
        }
        Expression::ContainsAny(expression) => {
            validate_query_in_expression_curry(expression.collection().expression())
                .and_then(|| validate_query_in_expression_curry(expression.elements().expression()))
        }
        Expression::Where(expression) => {
            validate_query_in_expression_curry(expression.expression().expression())
        }
        Expression::Query(query) => validate_query(authority, query.clone()),
        Expression::ContextValue(_) | Expression::Raw(_) => pass!(),
    }
}

macro_rules! tokens {
    (
        pattern = {
            $(#[$meta:meta])*
            $vis:vis struct _ {
                $(
                    $(#[$field_meta:meta])*
                    $field_vis:vis $field:ident: $field_type:ty
                ),* $(,)?
            }
        },
        $module:ident :: tokens: [$($name:ident),+ $(,)?]
    ) => {
        declare_tokens!($(
            crate::isi::$module::tokens::$name
        ),+);

        pub mod tokens {
            //! Permission tokens for concrete operations.

            use super::*;

            macro_rules! single_token {
                ($name_internal:ident) => {
                    $(#[$meta])*
                    $vis struct $name_internal {
                        $(
                            $(#[$field_meta])*
                            $field_vis $field: $field_type
                        ),*
                    }
                };
            }

            $(single_token!($name);)+
        }
    };
}

pub(crate) use tokens;
