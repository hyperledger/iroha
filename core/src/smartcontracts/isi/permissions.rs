//! Contains functions to check permission
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use iroha_data_model::isi::error::EvaluationError;

use super::*;

/// Verify that the given `instruction` is allowed to be executed
///
/// # Errors
///
/// If given instruction is not permitted to execute
#[allow(clippy::expect_used)]
pub fn check_instruction_permissions(
    account_id: &AccountId,
    instruction: &Instruction,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    let granted_instructions = &unpack_if_role_grant(instruction.clone(), wsv)
        .expect("Infallible. Evaluations have been checked by instruction execution.");
    check_permissions_directly(account_id, granted_instructions, wsv)?;

    let revoked_instructions = &unpack_if_role_revoke(instruction.clone(), wsv)
        .expect("Infallible. Evaluations have been checked by instruction execution.");
    check_permissions_directly(account_id, revoked_instructions, wsv)?;

    check_permission_recursively(account_id, instruction, wsv)?;

    check_query_in_instruction(account_id, instruction, wsv)
        .map_err(|error| NotPermittedFail {
            reason: error.to_string(),
        })
        .map_err(TransactionRejectionReason::NotPermitted)?;

    Ok(())
}

fn check_permission_recursively(
    authority: &AccountId,
    instruction: &Instruction,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    match instruction {
        Instruction::If(if_box) => check_permission_recursively(authority, &if_box.then, wsv)
            .and_then(|_| {
                if_box
                    .otherwise
                    .as_ref()
                    .map_or(Ok(()), |this_instruction| {
                        check_permission_recursively(authority, this_instruction, wsv)
                    })
            }),
        Instruction::Pair(pair_box) => {
            check_permission_recursively(authority, &pair_box.left_instruction, wsv).and_then(
                |_| check_permission_recursively(authority, &pair_box.right_instruction, wsv),
            )
        }
        Instruction::Sequence(sequence_box) => {
            sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| {
                    check_permission_recursively(authority, this_instruction, wsv)
                })
        }
        simple => check_permissions_directly(authority, &[simple.clone()], wsv),
    }
}

/// Verify that the given `query` is allowed to be executed
///
/// # Errors
///
/// If given query is not permitted to execute
pub fn check_query_permissions(
    account_id: &AccountId,
    query: &QueryBox,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    wsv.validators_view()
        .validate(wsv, account_id, query.clone())
        .map_err(|error| NotPermittedFail {
            reason: error.to_string(),
        })
        .map_err(TransactionRejectionReason::NotPermitted)
}

fn check_permissions_directly(
    account_id: &AccountId,
    instructions: &[Instruction],
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    for isi in instructions {
        wsv.validators_view()
            .validate(wsv, account_id, isi.clone())
            .map_err(|error| NotPermittedFail {
                reason: error.to_string(),
            })
            .map_err(TransactionRejectionReason::NotPermitted)?;
    }
    Ok(())
}

/// Checks an expression recursively to evaluate if there is a query
/// inside of it and if the user has permission to execute this query.
///
/// As the function is recursive, caution should be exercised to have
/// a nesting limit, that would not cause stack overflow.  Up to
/// 2^13 calls were tested and are ok. This is within default
/// instruction limit.
///
/// # Errors
/// If a user is not allowed to execute one of the inner queries,
/// given the current `judge`.
pub fn check_query_in_expression(
    authority: &AccountId,
    expression: &Expression,
    wsv: &WorldStateView,
) -> Result<()> {
    macro_rules! check_binary_expression {
        ($e:ident) => {
            check_query_in_expression(authority, &($e).left.expression, wsv)
                .and_then(|_| check_query_in_expression(authority, &($e).right.expression, wsv))
        };
    }

    match expression {
        Expression::Add(expression) => check_binary_expression!(expression),
        Expression::Subtract(expression) => check_binary_expression!(expression),
        Expression::Multiply(expression) => check_binary_expression!(expression),
        Expression::Divide(expression) => check_binary_expression!(expression),
        Expression::Mod(expression) => check_binary_expression!(expression),
        Expression::RaiseTo(expression) => check_binary_expression!(expression),
        Expression::Greater(expression) => check_binary_expression!(expression),
        Expression::Less(expression) => check_binary_expression!(expression),
        Expression::Equal(expression) => check_binary_expression!(expression),
        Expression::Not(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv)
        }
        Expression::And(expression) => check_binary_expression!(expression),
        Expression::Or(expression) => check_binary_expression!(expression),
        Expression::If(expression) => {
            check_query_in_expression(authority, &expression.condition.expression, wsv)
                .and(check_query_in_expression(
                    authority,
                    &expression.then_expression.expression,
                    wsv,
                ))
                .and(check_query_in_expression(
                    authority,
                    &expression.else_expression.expression,
                    wsv,
                ))
        }
        Expression::Contains(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv).and(
                check_query_in_expression(authority, &expression.element.expression, wsv),
            )
        }
        Expression::ContainsAll(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv).and(
                check_query_in_expression(authority, &expression.elements.expression, wsv),
            )
        }
        Expression::ContainsAny(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv).and(
                check_query_in_expression(authority, &expression.elements.expression, wsv),
            )
        }
        Expression::Where(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv)
        }
        Expression::Query(query) => {
            check_query_permissions(authority, query, wsv).map_err(Into::into)
        }
        Expression::ContextValue(_) | Expression::Raw(_) => Ok(()),
    }
}

/// Checks an instruction recursively to evaluate if there is a query
/// inside of it and if the user has permission to execute this query.
///
/// As the function is recursive, caution should be exercised to have
/// a limit of nesting, that would not cause stack overflow.  Up to
/// 2^13 calls were tested and are ok. This is within default
/// instruction limit.
///
/// # Errors
/// If a user is not allowed to execute one of the inner queries,
/// given the current [`Judge`].
#[allow(clippy::too_many_lines)]
pub fn check_query_in_instruction(
    authority: &AccountId,
    instruction: &Instruction,
    wsv: &WorldStateView,
) -> Result<()> {
    match instruction {
        Instruction::Register(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv)
        }
        Instruction::Unregister(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv)
        }
        Instruction::Mint(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv).and(
                check_query_in_expression(authority, &instruction.destination_id.expression, wsv),
            )
        }
        Instruction::Burn(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv).and(
                check_query_in_expression(authority, &instruction.destination_id.expression, wsv),
            )
        }
        Instruction::Transfer(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.source_id.expression,
                    wsv,
                ))
        }
        Instruction::SetKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv)
                .and(check_query_in_expression(
                    authority,
                    &instruction.key.expression,
                    wsv,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.value.expression,
                    wsv,
                ))
        }
        Instruction::RemoveKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv).and(
                check_query_in_expression(authority, &instruction.key.expression, wsv),
            )
        }
        Instruction::Grant(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv).and(
                check_query_in_expression(authority, &instruction.destination_id.expression, wsv),
            )
        }
        Instruction::Revoke(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv).and(
                check_query_in_expression(authority, &instruction.destination_id.expression, wsv),
            )
        }
        Instruction::If(if_box) => check_query_in_instruction(authority, &if_box.then, wsv)
            .and_then(|_| {
                if_box
                    .otherwise
                    .as_ref()
                    .map_or(Ok(()), |this_instruction| {
                        check_query_in_instruction(authority, this_instruction, wsv)
                    })
            }),
        Instruction::Pair(pair_box) => {
            check_query_in_instruction(authority, &pair_box.left_instruction, wsv).and(
                check_query_in_instruction(authority, &pair_box.right_instruction, wsv),
            )
        }
        Instruction::Sequence(sequence_box) => {
            sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| {
                    check_query_in_instruction(authority, this_instruction, wsv)
                })
        }
        Instruction::SetParameter(parameter_box) => {
            check_query_in_expression(authority, &parameter_box.parameter.expression, wsv)
        }
        Instruction::NewParameter(parameter_box) => {
            check_query_in_expression(authority, &parameter_box.parameter.expression, wsv)
        }
        Instruction::Fail(_) | Instruction::ExecuteTrigger(_) => Ok(()),
    }
}

/// Check if a permission `token` has the parameters from its `definition`.
///
/// Takes `O(max(N, M))` time, where *N* is the number of parameters in `token`
/// and *M* is the number of parameters in `definition`.
///
/// # Errors
/// Fails if there is a mismatch between a permissions `token` and its `definition`:
/// - If a `token` doesn't have all parameters from its `definition`
/// - If a `token` has parameters that are not in its `definition`
/// - If a `token` has a parameter of a different type than in its `definition`
pub fn check_permission_token_parameters(
    token: &PermissionToken,
    definition: &PermissionTokenDefinition,
) -> std::result::Result<(), EvaluationError> {
    use iroha_data_model::ValueKind;
    use itertools::{
        EitherOrBoth::{Both, Left, Right},
        Itertools,
    };

    for either_or_both in token
        .params
        .iter()
        .map(|(key, value)| (key, ValueKind::from(value)))
        .zip_longest(&definition.params)
    {
        match either_or_both {
            Both((key, kind), (expected_key, expected_kind)) => {
                // As keys are guaranteed to be in alphabetical order, that's an error if they are mismatched
                if key != expected_key {
                    return Err(missing_parameter(expected_key));
                }
                if kind != *expected_kind {
                    return Err(EvaluationError::PermissionParameter(format!(
                        "Permission token parameter `{key}` type mismatch: \
                         expected `{expected_kind}`, got `{kind}`"
                    )));
                }
            }
            // No more parameters in the definition
            Left((key, _)) => {
                return Err(EvaluationError::PermissionParameter(format!(
                    "Undefined permission token parameter: `{key}`"
                )));
            }
            // No more parameters in the permission token
            Right((expected_key, _)) => {
                return Err(missing_parameter(expected_key));
            }
        }
    }

    Ok(())
}

fn missing_parameter(key: &Name) -> EvaluationError {
    EvaluationError::PermissionParameter(format!("Permission parameter `{key}` is missing"))
}

/// Used in `unpack_` functions for role granting and revoking
#[rustfmt::skip] // Works weirdly with let-else expressions
macro_rules! unpack {
    ($i:ident, $w:ident, Instruction::$v:ident => $t:ty) => {{
        let Instruction::$v(operation) = &$i else {
            return Ok(vec![$i]);
        };
        let Value::Id(IdBox::RoleId(id)) = operation.object.evaluate(&Context::new($w))? else {
            return Ok(vec![$i]);
        };

        let instructions = if let Some(role) = $w.world.roles.get(&id) {
            let destination_id = operation.destination_id.evaluate(&Context::new($w))?;
            role.permissions()
                .cloned()
                .map(|permission_token| <$t>::new(permission_token, destination_id.clone()).into())
                .collect()
        } else {
            Vec::new()
        };
        Ok(instructions)
    }};
}

/// Unpacks instruction if it is Grant of a Role into several Grants
/// fo Permission Token.  If instruction is not Grant of Role, returns
/// it as inly instruction inside the vec.  Should be called before
/// permission checks by validators.
///
/// Semantically means that user can grant a role only if they can
/// grant each of the permission tokens that the role consists of.
///
/// # Errors
/// Evaluation failure of instruction fields.
pub fn unpack_if_role_grant(
    instruction: Instruction,
    wsv: &WorldStateView,
) -> eyre::Result<Vec<Instruction>> {
    unpack!(instruction, wsv, Instruction::Grant => GrantBox)
}

/// Unpack instruction if it is a Revoke of a Role, into several
/// Revocations of Permission Tokens. If the instruction is not a
/// Revoke of Role, returns it as an internal instruction inside the
/// vec.
///
/// This `fn` should be called before permission checks (by
/// validators).
///
/// Semantically: the user can revoke a role only if they can revoke
/// each of the permission tokens that the role consists of of.
///
/// # Errors
/// Evaluation failure of each of the instruction fields.
pub fn unpack_if_role_revoke(
    instruction: Instruction,
    wsv: &WorldStateView,
) -> eyre::Result<Vec<Instruction>> {
    unpack!(instruction, wsv, Instruction::Revoke => RevokeBox)
}
