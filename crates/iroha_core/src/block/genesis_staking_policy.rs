//! Staking authority derived only from the configured-root authenticated genesis source.
//!
//! This capability authenticates the selected original instruction and unpublished State
//! overlay. It does not certify allocation admission. TODO(F4): admit and retain original
//! custom-parameter, AccountId and Quantity backing through the canonical parameter MV
//! owner before live adoption; author all genesis policies and retire monetary config
//! only with the complete consumer migration.

use iroha_data_model::{
    block::consensus::{PublicLaneStakingPolicy, PublicLaneStakingPolicyError},
    block::{BlockHeader, SignedBlock},
    isi::SetParameter,
    parameter::{CustomParameter, Parameter},
    transaction::Executable,
};

use super::{AuthenticatedGenesisOutputSource, BlockValidationError, InvalidGenesisError};
use crate::{
    execution_attempt::{ExecutionAttemptError, canonical_decode_attempt_error},
    state::StateBlock,
};

/// A private original-source selection; a height-one header cannot construct it.
#[derive(Debug)]
pub(crate) struct GenesisStakingPolicy {
    header: BlockHeader,
    coordinate: (usize, usize),
    parameter: CustomParameter,
    policy: PublicLaneStakingPolicy,
}

fn invalid(message: impl Into<String>) -> BlockValidationError {
    InvalidGenesisError::StakingPolicy(message.into()).into()
}

fn decoding(error: norito::core::DecodeAttemptError) -> BlockValidationError {
    match canonical_decode_attempt_error(error, |error| invalid(error.to_string())) {
        ExecutionAttemptError::Rejected(error) => error,
        ExecutionAttemptError::Deferred(original) => {
            BlockValidationError::ExecutionDeferred(original)
        }
    }
}

impl AuthenticatedGenesisOutputSource {
    /// Select the sole explicit policy after configured-root source authentication.
    /// Duplicate assignments are invalid even if they encode the same policy.
    pub(crate) fn initial_staking_policy(
        &self,
        block: &SignedBlock,
    ) -> Result<GenesisStakingPolicy, BlockValidationError> {
        self.account_for(block).map_err(invalid)?;
        let mut selected = None;
        for (transaction_index, transaction) in block.external_transactions().enumerate() {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                return Err(invalid(
                    "genesis policy requires original explicit instructions",
                ));
            };
            for (instruction_index, instruction) in instructions.iter().enumerate() {
                let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                    continue;
                };
                let Parameter::Custom(custom) = set.inner() else {
                    continue;
                };
                if custom.id() != &PublicLaneStakingPolicy::parameter_id() {
                    continue;
                }
                if selected.is_some() {
                    return Err(invalid(
                        "genesis repeats its initial staking monetary policy",
                    ));
                }
                selected = Some(((transaction_index, instruction_index), custom));
            }
        }
        let (coordinate, parameter) =
            selected.ok_or_else(|| invalid("genesis omits its initial staking monetary policy"))?;
        let policy = norito::core::classify_decode_attempt(|| {
            PublicLaneStakingPolicy::from_custom_parameter(parameter).map_err(|error| match error {
                PublicLaneStakingPolicyError::Codec(original) => original,
                invalid => norito::Error::Message(invalid.to_string()),
            })
        })
        .map_err(decoding)?;
        Ok(GenesisStakingPolicy {
            header: block.header(),
            coordinate,
            parameter: parameter.clone(),
            policy,
        })
    }
}

impl GenesisStakingPolicy {
    /// Move authentication evidence into the exact overlay only after installation succeeds.
    /// On refusal the caller retains its original capability for retry.
    #[cfg(test)]
    pub(crate) fn install(
        original: &mut Option<Self>,
        block: &SignedBlock,
        state: &mut StateBlock<'_>,
        source_state: &crate::state::State,
        generation: u64,
    ) -> Result<(), BlockValidationError> {
        if state.genesis_staking_policy.is_some() {
            return Err(invalid(
                "genesis overlay already retains its initial policy capability",
            ));
        }
        let selected = original
            .as_ref()
            .ok_or_else(|| invalid("initial policy capability was already consumed"))?;
        selected.initialize_parameters(block, state, source_state, generation)?;
        state.genesis_staking_policy = original.take();
        Ok(())
    }

    /// Authenticate the original parameter value before lending its policy to a child.
    pub(crate) fn policy_for_parameters<'a>(
        &self,
        header: &BlockHeader,
        owner: &'a crate::pipeline_gas_policy::StateParameters,
    ) -> Result<&'a PublicLaneStakingPolicy, PublicLaneStakingPolicyError> {
        if header != &self.header
            || owner.staking_policy() != Some(&self.policy)
            || owner.custom().get(&PublicLaneStakingPolicy::parameter_id()) != Some(&self.parameter)
        {
            return Err(PublicLaneStakingPolicyError::GenesisSourceMismatch);
        }
        owner.require_staking_policy()
    }

    /// Require the actual genesis instruction to repeat the selected original bytes.
    /// No decoded equivalent or transaction-local initialization grants authority.
    pub(crate) fn require_parameter(
        &self,
        header: &BlockHeader,
        owner: &crate::pipeline_gas_policy::StateParameters,
        parameter: &CustomParameter,
    ) -> Result<(), PublicLaneStakingPolicyError> {
        self.policy_for_parameters(header, owner)?;
        if parameter != &self.parameter {
            return Err(PublicLaneStakingPolicyError::GenesisSourceMismatch);
        }
        Ok(())
    }

    /// Validate this original source against the still-pristine overlay.
    /// The combined bootstrap calls both validators before changing any parameter.
    pub(super) fn validate_installation(
        &self,
        block: &SignedBlock,
        state: &StateBlock<'_>,
        original: &crate::state::State,
        generation: u64,
    ) -> Result<(), BlockValidationError> {
        // A retained header and selected policy coordinate alone cannot bind the
        // remaining original inputs or DA sidecars. Reject substitution before
        // acquiring a mutable parameter owner.
        block.validate_proposal_commitments().map_err(invalid)?;
        state
            .require_original_execution_recorder()
            .map_err(invalid)?;
        state
            .validate_native_pristine_control_owner(original, generation, &self.header)
            .map_err(invalid)?;
        if block.header() != self.header
            || state._curr_block != self.header
            || !state.block_hashes.is_empty()
        {
            return Err(invalid(
                "initial staking policy belongs to another genesis source or State history",
            ));
        }
        let transaction = block
            .external_transactions()
            .nth(self.coordinate.0)
            .ok_or_else(|| invalid("initial staking policy source transaction is absent"))?;
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(invalid(
                "initial staking policy source is not explicit instructions",
            ));
        };
        let selected = instructions
            .get(self.coordinate.1)
            .and_then(|instruction| instruction.as_any().downcast_ref::<SetParameter>());
        if !matches!(selected.map(SetParameter::inner), Some(Parameter::Custom(custom)) if custom == &self.parameter)
        {
            return Err(invalid("initial staking policy source instruction changed"));
        }
        let owner = state.world.parameters.get();
        if owner.staking_policy().is_some() {
            return Err(invalid(
                "pre-genesis State already contains a staking monetary policy",
            ));
        }
        Ok(())
    }

    /// Decode into the unpublished combined candidate; this grants no State authority.
    /// The caller retains both original capabilities until every policy succeeds.
    pub(super) fn initialize_candidate(
        &self,
        owner: &mut crate::pipeline_gas_policy::StateParameters,
    ) -> Result<(), BlockValidationError> {
        if owner.staking_policy().is_some() {
            return Err(invalid(
                "pre-genesis State already contains a staking monetary policy",
            ));
        }
        norito::core::classify_decode_attempt(|| {
            owner.set_parameter(Parameter::Custom(self.parameter.clone()))
        })
        .map_err(decoding)?;
        Ok(())
    }

    /// Initialize only the same unpublished original empty-history overlay.
    /// The enclosing pristine stage already owns its original recorder.
    #[cfg(test)]
    fn initialize_parameters(
        &self,
        block: &SignedBlock,
        state: &mut StateBlock<'_>,
        original: &crate::state::State,
        generation: u64,
    ) -> Result<(), BlockValidationError> {
        self.validate_installation(block, state, original, generation)?;
        self.initialize_candidate(state.world.parameters.get_mut())?;
        self.require_unchanged(state)
    }

    /// A later genesis instruction cannot replace the authenticated initial value.
    pub(crate) fn require_unchanged(
        &self,
        state: &StateBlock<'_>,
    ) -> Result<(), BlockValidationError> {
        let owner = state.world.parameters.get();
        if state._curr_block != self.header
            || owner.staking_policy() != Some(&self.policy)
            || owner.custom().get(&PublicLaneStakingPolicy::parameter_id()) != Some(&self.parameter)
        {
            return Err(invalid(
                "executed genesis changed its authenticated initial staking monetary policy",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
