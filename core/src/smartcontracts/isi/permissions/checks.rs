//! Contains functions to check permission

use super::{judge::Judge, *};

/// Verify that the given `instruction` is allowed to execute
///
/// # Errors
///
/// If given instruction is not permitted to execute
#[allow(clippy::expect_used)]
pub fn check_instruction_permissions(
    account_id: &AccountId,
    instruction: &Instruction,
    is_instruction_allowed: &dyn Judge<Operation = Instruction>,
    is_query_allowed: &dyn Judge<Operation = QueryBox>,
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
    is_instruction_allowed: &dyn Judge<Operation = Instruction>,
    wsv: &WorldStateView,
) -> std::result::Result<(), TransactionRejectionReason> {
    for isi in instructions {
        is_instruction_allowed
            .judge(account_id, isi, wsv)
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
/// a limit of nesting, that would not cause stack overflow.  Up to
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
    is_query_allowed: &dyn Judge<Operation = QueryBox>,
) -> Result<()> {
    macro_rules! check_binary_expression {
        ($e:ident) => {
            check_query_in_expression(authority, &($e).left.expression, wsv, is_query_allowed).and(
                check_query_in_expression(authority, &($e).right.expression, wsv, is_query_allowed),
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
            is_query_allowed,
        ),
        Expression::And(expression) => check_binary_expression!(expression),
        Expression::Or(expression) => check_binary_expression!(expression),
        Expression::If(expression) => check_query_in_expression(
            authority,
            &expression.condition.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &expression.then_expression.expression,
            wsv,
            is_query_allowed,
        ))
        .and(check_query_in_expression(
            authority,
            &expression.else_expression.expression,
            wsv,
            is_query_allowed,
        )),
        Expression::Query(query) => is_query_allowed.judge(authority, query, wsv),
        Expression::Contains(expression) => check_query_in_expression(
            authority,
            &expression.collection.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &expression.element.expression,
            wsv,
            is_query_allowed,
        )),
        Expression::ContainsAll(expression) => check_query_in_expression(
            authority,
            &expression.collection.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &expression.elements.expression,
            wsv,
            is_query_allowed,
        )),
        Expression::ContainsAny(expression) => check_query_in_expression(
            authority,
            &expression.collection.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &expression.elements.expression,
            wsv,
            is_query_allowed,
        )),
        Expression::Where(expression) => check_query_in_expression(
            authority,
            &expression.expression.expression,
            wsv,
            is_query_allowed,
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
/// # Panic
///
/// Function will panic if at least one the the following invariants is not met:
/// - Calling [`GetValidatorType::get_validator_type`]
/// on `is_query_allowed` should return [`ValidatorType::Query`]
///
/// # Errors
/// If a user is not allowed to execute one of the inner queries,
/// given the current `judge`.
#[allow(clippy::too_many_lines)]
pub fn check_query_in_instruction(
    authority: &AccountId,
    instruction: &Instruction,
    wsv: &WorldStateView,
    is_query_allowed: &dyn Judge<Operation = QueryBox>,
) -> Result<()> {
    match instruction {
        Instruction::Register(instruction) => check_query_in_expression(
            authority,
            &instruction.object.expression,
            wsv,
            is_query_allowed,
        ),
        Instruction::Unregister(instruction) => check_query_in_expression(
            authority,
            &instruction.object_id.expression,
            wsv,
            is_query_allowed,
        ),
        Instruction::Mint(instruction) => check_query_in_expression(
            authority,
            &instruction.object.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.destination_id.expression,
            wsv,
            is_query_allowed,
        )),
        Instruction::Burn(instruction) => check_query_in_expression(
            authority,
            &instruction.object.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.destination_id.expression,
            wsv,
            is_query_allowed,
        )),
        Instruction::Transfer(instruction) => check_query_in_expression(
            authority,
            &instruction.object.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.destination_id.expression,
            wsv,
            is_query_allowed,
        ))
        .and(check_query_in_expression(
            authority,
            &instruction.source_id.expression,
            wsv,
            is_query_allowed,
        )),
        Instruction::SetKeyValue(instruction) => check_query_in_expression(
            authority,
            &instruction.object_id.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.key.expression,
            wsv,
            is_query_allowed,
        ))
        .and(check_query_in_expression(
            authority,
            &instruction.value.expression,
            wsv,
            is_query_allowed,
        )),
        Instruction::RemoveKeyValue(instruction) => check_query_in_expression(
            authority,
            &instruction.object_id.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.key.expression,
            wsv,
            is_query_allowed,
        )),
        Instruction::Grant(instruction) => check_query_in_expression(
            authority,
            &instruction.object.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.destination_id.expression,
            wsv,
            is_query_allowed,
        )),
        Instruction::Revoke(instruction) => check_query_in_expression(
            authority,
            &instruction.object.expression,
            wsv,
            is_query_allowed,
        )
        .and(check_query_in_expression(
            authority,
            &instruction.destination_id.expression,
            wsv,
            is_query_allowed,
        )),
        Instruction::If(if_box) => check_query_in_instruction(
            authority,
            &if_box.then,
            wsv,
            is_query_allowed,
        )
        .and_then(|_| match &if_box.otherwise {
            Some(this_instruction) => {
                check_query_in_instruction(authority, this_instruction, wsv, is_query_allowed)
            }
            None => Ok(()),
        }),
        Instruction::Pair(pair_box) => {
            check_query_in_instruction(authority, &pair_box.left_instruction, wsv, is_query_allowed)
                .and(check_query_in_instruction(
                    authority,
                    &pair_box.right_instruction,
                    wsv,
                    is_query_allowed,
                ))
        }
        Instruction::Sequence(sequence_box) => {
            sequence_box
                .instructions
                .iter()
                .try_for_each(|this_instruction| {
                    check_query_in_instruction(authority, this_instruction, wsv, is_query_allowed)
                })
        }
        Instruction::Fail(_) | Instruction::ExecuteTrigger(_) => Ok(()),
    }
}
