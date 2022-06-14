//! Contains functions to check permission

use super::*;

/// Verify that the given instruction is allowed to execute
///
/// # Errors
///
/// If given instruction is not permitted to execute
#[allow(clippy::expect_used)]
pub fn check_instruction_permissions(
    account_id: &AccountId,
    instruction: &Instruction,
    is_instruction_allowed: &IsInstructionAllowedBoxed,
    is_query_allowed: &IsQueryAllowedBoxed,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    let granted_instructions = &super::roles::unpack_if_role_grant(instruction.clone(), wsv)
        .expect("Infallible. Evaluations have been checked by instruction execution.");
    check_permissions_directly(
        account_id,
        granted_instructions,
        is_instruction_allowed,
        wsv,
    )?;

    let revoked_instructions = &super::roles::unpack_if_role_revoke(instruction.clone(), wsv)
        .expect("Infallible. Evaluations have been checked by instruction execution.");
    check_permissions_directly(
        account_id,
        revoked_instructions,
        is_instruction_allowed,
        wsv,
    )?;

    check_query_in_instruction(account_id, instruction, wsv, is_query_allowed)
        .map_err(|reason| NotPermittedFail {
            reason: reason.to_string(),
        })
        .map_err(TransactionRejectionReason::NotPermitted)?;

    Ok(())
}

fn check_permissions_directly(
    account_id: &AccountId,
    instructions: &[Instruction],
    is_instruction_allowed: &IsInstructionAllowedBoxed,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    for isi in instructions {
        is_instruction_allowed
            .check(account_id, isi, wsv)
            .map_err(|reason| NotPermittedFail {
                reason: reason.to_string(),
            })
            .map_err(TransactionRejectionReason::NotPermitted)?;
    }
    Ok(())
}

/// Checks an expression recursively to evaluate if there is a query
/// inside of it and if the user has permission to execute this query.
///
/// As the function is recursive, caution should be exercised to have
/// a limit of nestedness, that would not cause stack overflow.  Up to
/// 2^13 calls were tested and are ok. This is within default
/// instruction limit.
///
/// # Errors
/// If a user is not allowed to execute one of the inner queries,
/// given the current `validator`.
pub fn check_query_in_expression(
    authority: &AccountId,
    expression: &Expression,
    wsv: &WorldStateView,
    validator: &IsQueryAllowedBoxed,
) -> Result<()> {
    macro_rules! check_binary_expression {
        ($e:ident) => {
            check_query_in_expression(authority, &($e).left.expression, wsv, validator).and(
                check_query_in_expression(authority, &($e).right.expression, wsv, validator),
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
        Expression::Not(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv, validator)
        }
        Expression::And(expression) => check_binary_expression!(expression),
        Expression::Or(expression) => check_binary_expression!(expression),
        Expression::If(expression) => {
            check_query_in_expression(authority, &expression.condition.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.then_expression.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &expression.else_expression.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::Query(query) => validator.check(authority, query, wsv),
        Expression::Contains(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.element.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::ContainsAll(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.elements.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::ContainsAny(expression) => {
            check_query_in_expression(authority, &expression.collection.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &expression.elements.expression,
                    wsv,
                    validator,
                ))
        }
        Expression::Where(expression) => {
            check_query_in_expression(authority, &expression.expression.expression, wsv, validator)
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
/// given the current `validator`.
#[allow(clippy::too_many_lines)]
pub fn check_query_in_instruction(
    authority: &AccountId,
    instruction: &Instruction,
    wsv: &WorldStateView,
    validator: &IsQueryAllowedBoxed,
) -> Result<()> {
    match instruction {
        Instruction::Register(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
        }
        Instruction::Unregister(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
        }
        Instruction::Mint(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Burn(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Transfer(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.source_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::SetKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.key.expression,
                    wsv,
                    validator,
                ))
                .and(check_query_in_expression(
                    authority,
                    &instruction.value.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::RemoveKeyValue(instruction) => {
            check_query_in_expression(authority, &instruction.object_id.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.key.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Grant(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::Revoke(instruction) => {
            check_query_in_expression(authority, &instruction.object.expression, wsv, validator)
                .and(check_query_in_expression(
                    authority,
                    &instruction.destination_id.expression,
                    wsv,
                    validator,
                ))
        }
        Instruction::If(if_box) => {
            check_query_in_instruction(authority, &if_box.then, wsv, validator).and_then(|_| {
                match &if_box.otherwise {
                    Some(this_instruction) => {
                        check_query_in_instruction(authority, this_instruction, wsv, validator)
                    }
                    None => Ok(()),
                }
            })
        }
        Instruction::Pair(pair_box) => {
            check_query_in_instruction(authority, &pair_box.left_instruction, wsv, validator).and(
                check_query_in_instruction(authority, &pair_box.right_instruction, wsv, validator),
            )
        }
        Instruction::Sequence(sequence_box) => {
            sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| {
                    check_query_in_instruction(authority, this_instruction, wsv, validator)
                })
        }
        Instruction::Fail(_) | Instruction::ExecuteTrigger(_) => Ok(()),
    }
}
