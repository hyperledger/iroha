//! Atomic installation of both original signed-genesis policy capabilities.
//!
//! Validate the pristine State once for the complete bootstrap operation. Each
//! source-specific validator runs before either projection changes. Decode into
//! a disposable candidate, then move both capabilities and the candidate together.
//! TODO(F4): fund the canonical parameter/MV backing and nested leaves before
//! live adoption; this source-authentication owner does not claim allocation custody.

use iroha_data_model::block::SignedBlock;

use super::{
    AuthenticatedGenesisOutputSource, BlockValidationError, InvalidGenesisError,
    genesis_crypto_policy::GenesisCryptoPolicy, genesis_staking_policy::GenesisStakingPolicy,
};
use crate::state::{State, StateBlock};

/// Both policies selected from the same original authenticated signed source.
#[derive(Debug)]
pub(crate) struct GenesisPolicies {
    crypto: GenesisCryptoPolicy,
    staking: GenesisStakingPolicy,
}

impl AuthenticatedGenesisOutputSource {
    /// Select both mandatory policies without giving an ordinary caller bootstrap authority.
    pub(crate) fn initial_policies(
        &self,
        block: &SignedBlock,
    ) -> Result<GenesisPolicies, BlockValidationError> {
        Ok(GenesisPolicies {
            crypto: self.initial_crypto_policy(block)?,
            staking: self.initial_staking_policy(block)?,
        })
    }
}

impl GenesisPolicies {
    /// Install both projections at one verified original pristine State cut.
    /// Any source or decoder refusal leaves State and both source capabilities intact.
    pub(crate) fn install(
        original: &mut Option<Self>,
        block: &SignedBlock,
        overlay: &mut StateBlock<'_>,
        state: &State,
        generation: u64,
    ) -> Result<(), BlockValidationError> {
        let invalid = |message: &str| {
            BlockValidationError::from(InvalidGenesisError::StakingPolicy(message.into()))
        };
        if overlay.genesis_crypto_policy.is_some() || overlay.genesis_staking_policy.is_some() {
            return Err(invalid(
                "genesis overlay already retains an initial policy capability",
            ));
        }
        let selected = original
            .as_ref()
            .ok_or_else(|| invalid("combined initial policy capability was already consumed"))?;
        // Both checks still require an empty execution write-set. Neither is
        // weakened to permit the writes of a previously installed policy.
        selected
            .crypto
            .validate_installation(block, overlay, state, generation)?;
        selected
            .staking
            .validate_installation(block, overlay, state, generation)?;
        let mut candidate = overlay.world.parameters.get().clone();
        selected.crypto.initialize_candidate(&mut candidate)?;
        selected.staking.initialize_candidate(&mut candidate)?;
        selected
            .crypto
            .policy_for_parameters(&block.header(), &candidate)
            .map_err(|_| invalid("combined candidate lost its original crypto policy"))?;
        selected
            .staking
            .policy_for_parameters(&block.header(), &candidate)
            .map_err(|_| invalid("combined candidate lost its original staking policy"))?;
        // No fallible decoder or source check follows the first overlay write.
        // Both retained source owners move with their exact validated projections.
        *overlay.world.parameters.get_mut() = candidate;
        let selected = original
            .take()
            .expect("checked original combined capability");
        overlay.genesis_crypto_policy = Some(selected.crypto);
        overlay.genesis_staking_policy = Some(selected.staking);
        Ok(())
    }
}
