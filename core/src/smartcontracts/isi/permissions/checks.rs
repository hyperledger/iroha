//! Contains functions to check permission
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use super::{judge::Judge, *};

/// Verify that the given `instruction` is allowed to be executed
///
/// # Errors
///
/// If given instruction is not permitted to execute
#[allow(clippy::expect_used)]
pub fn check_instruction_permissions(
    account_id: &AccountId,
    instruction: &Instruction,
    instruction_judge: &dyn Judge<Operation = Instruction>,
    query_judge: &dyn Judge<Operation = QueryBox>,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    let granted_instructions = &super::roles::unpack_if_role_grant(instruction.clone(), wsv)
        .expect("Infallible. Evaluations have been checked by instruction execution.");
    check_permissions_directly(account_id, granted_instructions, instruction_judge, wsv)?;

    let revoked_instructions = &super::roles::unpack_if_role_revoke(instruction.clone(), wsv)
        .expect("Infallible. Evaluations have been checked by instruction execution.");
    check_permissions_directly(account_id, revoked_instructions, instruction_judge, wsv)?;

    check_query_in_instruction(account_id, instruction, wsv, query_judge)
        .map_err(|reason| NotPermittedFail { reason })
        .map_err(TransactionRejectionReason::NotPermitted)?;

    Ok(())
}

fn check_permissions_directly(
    account_id: &AccountId,
    instructions: &[Instruction],
    is_instruction_allowed: &dyn Judge<Operation = Instruction>,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    for isi in instructions {
        is_instruction_allowed
            .judge(account_id, isi, wsv)
            .map_err(|reason| NotPermittedFail { reason })
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
    query_judge: &dyn Judge<Operation = QueryBox>,
) -> Result<()> {
    macro_rules! check_binary_expression {
        ($e:ident) => {
            check_query_in_expression(authority, &($e).left.expression, wsv, query_judge).and(
                check_query_in_expression(authority, &($e).right.expression, wsv, query_judge),
            )
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
        Expression::Not(expression) => check_query_in_expression(
            authority,
            &expression.expression.expression,
            wsv,
            query_judge,
        ),
        Expression::And(expression) => check_binary_expression!(expression),
        Expression::Or(expression) => check_binary_expression!(expression),
        Expression::If(expression) => check_query_in_expression(
            authority,
            &expression.condition.expression,
            wsv,
            query_judge,
        )
        .and(check_query_in_expression(
            authority,
            &expression.then_expression.expression,
            wsv,
            query_judge,
        ))
        .and(check_query_in_expression(
            authority,
            &expression.else_expression.expression,
            wsv,
            query_judge,
        )),
        Expression::Query(query) => query_judge.judge(authority, query, wsv),
        Expression::Contains(expression) => check_query_in_expression(
            authority,
            &expression.collection.expression,
            wsv,
            query_judge,
        )
        .and(check_query_in_expression(
            authority,
            &expression.element.expression,
            wsv,
            query_judge,
        )),
        Expression::ContainsAll(expression) => check_query_in_expression(
            authority,
            &expression.collection.expression,
            wsv,
            query_judge,
        )
        .and(check_query_in_expression(
            authority,
            &expression.elements.expression,
            wsv,
            query_judge,
        )),
        Expression::ContainsAny(expression) => check_query_in_expression(
            authority,
            &expression.collection.expression,
            wsv,
            query_judge,
        )
        .and(check_query_in_expression(
            authority,
            &expression.elements.expression,
            wsv,
            query_judge,
        )),
        Expression::Where(expression) => check_query_in_expression(
            authority,
            &expression.expression.expression,
            wsv,
            query_judge,
        ),
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
    query_judge: &dyn Judge<Operation = QueryBox>,
) -> Result<()> {
    match instruction {
        Instruction::Register(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, query_judge)
        }
        Instruction::Unregister(instruction) => check_query_in_expression(
            authority,
            &instruction.object_id.expression,
            wsv,
            query_judge,
        ),
        Instruction::Mint(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, query_judge)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    query_judge,
                ))
        }
        Instruction::Burn(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, query_judge)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    query_judge,
                ))
        }
        Instruction::Transfer(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, query_judge)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    query_judge,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.source_id.expression,
                    wsv,
                    query_judge,
                ))
        }
        Instruction::SetKeyValue(instruction) => check_query_in_expression(
            authority,
            &instruction.object_id.expression,
            wsv,
            query_judge,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.key.expression,
            wsv,
            query_judge,
        ))
        .and(check_query_in_expression(
            authority,
            &instruction.value.expression,
            wsv,
            query_judge,
        )),
        Instruction::RemoveKeyValue(instruction) => check_query_in_expression(
            authority,
            &instruction.object_id.expression,
            wsv,
            query_judge,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.key.expression,
            wsv,
            query_judge,
        )),
        Instruction::Grant(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, query_judge)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    query_judge,
                ))
        }
        Instruction::Revoke(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, query_judge)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    query_judge,
                ))
        }
        Instruction::If(if_box) => {
            check_query_in_instruction(authority, &if_box.then, wsv, query_judge).and_then(|_| {
                if_box
                    .otherwise
                    .as_ref()
                    .map_or(Ok(()), |this_instruction| {
                        check_query_in_instruction(authority, this_instruction, wsv, query_judge)
                    })
            })
        }
        Instruction::Pair(pair_box) => {
            check_query_in_instruction(authority, &pair_box.left_instruction, wsv, query_judge).and(
                check_query_in_instruction(
                    authority,
                    &pair_box.right_instruction,
                    wsv,
                    query_judge,
                ),
            )
        }
        Instruction::Sequence(sequence_box) => {
            sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| {
                    check_query_in_instruction(authority, this_instruction, wsv, query_judge)
                })
        }
        Instruction::SetParameter(parameter_box) => check_query_in_expression(
            authority,
            &parameter_box.parameter.expression,
            wsv,
            query_judge,
        ),
        Instruction::NewParameter(parameter_box) => check_query_in_expression(
            authority,
            &parameter_box.parameter.expression,
            wsv,
            query_judge,
        ),
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
) -> std::result::Result<(), ValidationError> {
    use iroha_data_model::ValueKind;
    use itertools::{
        EitherOrBoth::{Both, Left, Right},
        Itertools,
    };

    for either_or_both in token
        .params()
        .map(|(key, value)| (key, ValueKind::from(value)))
        .zip_longest(definition.params())
    {
        match either_or_both {
            Both((key, kind), (expected_key, expected_kind)) => {
                // As keys are guaranteed to be in alphabetical order, that's an error if they are mismatched
                if key != expected_key {
                    return Err(missing_parameter(expected_key));
                }
                if kind != *expected_kind {
                    return Err(ValidationError::new(format!(
                        "Permission token parameter `{key}` type mismatch: \
                         expected `{expected_kind}`, got `{kind}`"
                    )));
                }
            }
            // No more parameters in the definition
            Left((key, _)) => {
                return Err(ValidationError::new(format!(
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

fn missing_parameter(key: &Name) -> ValidationError {
    ValidationError::new(format!("Permission parameter `{key}` is missing"))
}
