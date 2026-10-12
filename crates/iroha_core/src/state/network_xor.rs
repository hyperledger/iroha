//! Canonical network currency shared by staking, rewards and restored custody.

use crate::{execution_attempt::ExecutionAttemptError as Attempt, state::WorldReadOnly};
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinitionId, AssetId},
    isi::error::InstructionExecutionError as Error,
};

/// Check the immutable definition shape without decoding policy a second time.
pub(crate) fn validate_xor_definition_shape<W: WorldReadOnly + ?Sized>(
    world: &W,
    asset: &AssetDefinitionId,
) -> Result<(), Error> {
    if cfg!(all(test, sumeragi_core_mutation = "HC58")) {
        return Ok(());
    }
    let definition = world.asset_definition(asset).map_err(Error::from)?;
    if definition.spec().scale() != Some(9)
        || definition.balance_scope_policy() != AssetBalancePolicy::Global
    {
        return Err(Error::InvariantViolation(
            "staking and rewards require global network XOR with scale nine".into(),
        ));
    }
    Ok(())
}

/// Retain the exact asset identity and reject scoped custody rather than rewriting it.
pub(crate) fn validate_xor_custody_shape<W: WorldReadOnly + ?Sized>(
    world: &W,
    asset: &AssetId,
) -> Result<(), Error> {
    validate_xor_definition_shape(world, asset.definition())?;
    if asset.scope() != &AssetBalanceScope::Global {
        return Err(Error::InvariantViolation(
            "staking and rewards require exact global XOR custody".into(),
        ));
    }
    Ok(())
}

/// Authenticate the genesis-pinned currency and its global scale-nine definition.
pub(crate) fn validate_network_xor_asset<W: WorldReadOnly + ?Sized>(
    world: &W,
    asset: &AssetDefinitionId,
) -> Result<(), Attempt<Error>> {
    if cfg!(all(test, sumeragi_core_mutation = "HC58")) {
        return Ok(());
    }
    let parameters = world
        .sumeragi_npos_parameters()
        .map_err(|error| error.map_rejection(|message| Error::InvariantViolation(message.into())))?
        .ok_or_else(|| {
            Error::InvariantViolation(
                "staking and rewards require the committed network XOR identity".into(),
            )
        })?;
    if asset != &parameters.xor_asset_definition_id {
        return Err(Error::InvariantViolation(
            "staking or reward asset differs from the committed network XOR identity".into(),
        )
        .into());
    }
    validate_xor_definition_shape(world, asset)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::World;
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::AssetDefinition,
        parameter::{Parameter, system::SumeragiNposParameters},
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use iroha_primitives::numeric::NumericSpec;
    use iroha_test_samples::ALICE_ID;

    #[test]
    fn network_xor_rejects_wrong_definition_scope_and_precision() {
        let parameters = SumeragiNposParameters::default();
        let xor = parameters.xor_asset_definition_id.clone();
        let mut world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        {
            let mut policy = world.parameters.block();
            policy
                .get_mut()
                .set_parameter(Parameter::Custom(parameters.into_custom_parameter()))
                .expect("valid fixture parameters");
            policy.commit();
        }
        for (spec, scope) in [
            (NumericSpec::fractional(9), AssetBalancePolicy::Global),
            (NumericSpec::default(), AssetBalancePolicy::Global),
            (NumericSpec::fractional(18), AssetBalancePolicy::Global),
            (
                NumericSpec::fractional(9),
                AssetBalancePolicy::DataspaceRestricted,
            ),
        ] {
            world.asset_definitions.insert(
                xor.clone(),
                AssetDefinition::new(xor.clone(), "XOR", spec, scope, None).build(&ALICE_ID),
            );
            let result = validate_network_xor_asset(&world.view(), &xor);
            if spec == NumericSpec::fractional(9) && scope == AssetBalancePolicy::Global {
                result.unwrap();
                validate_xor_custody_shape(
                    &world.view(),
                    &AssetId::new(xor.clone(), ALICE_ID.clone()),
                )
                .unwrap();
                let scoped = AssetId::with_scope(
                    xor.clone(),
                    ALICE_ID.clone(),
                    AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
                );
                assert!(
                    validate_xor_custody_shape(&world.view(), &scoped)
                        .unwrap_err()
                        .to_string()
                        .contains("exact global XOR custody")
                );
                let wrong = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wrong", "universal").unwrap(),
                    "xor".parse().unwrap(),
                );
                assert!(
                    validate_network_xor_asset(&world.view(), &wrong)
                        .unwrap_err()
                        .to_string()
                        .contains("committed network XOR")
                );
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("global network XOR with scale nine")
                );
            }
        }
    }
}
