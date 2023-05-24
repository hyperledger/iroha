//! Contains functions to check permission
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]

use super::*;

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
) -> std::result::Result<(), InstructionEvaluationError> {
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
                    return Err(InstructionEvaluationError::PermissionParameter(format!(
                        "Permission token parameter `{key}` type mismatch: \
                         expected `{expected_kind}`, got `{kind}`"
                    )));
                }
            }
            // No more parameters in the definition
            Left((key, _)) => {
                return Err(InstructionEvaluationError::PermissionParameter(format!(
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

fn missing_parameter(key: &Name) -> InstructionEvaluationError {
    InstructionEvaluationError::PermissionParameter(format!(
        "Permission parameter `{key}` is missing"
    ))
}
