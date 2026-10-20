//! Immutable candidate selection from the original signed genesis instruction.
//!
//! The authenticated selection is source data. Only its exact direct native Initial
//! executor frame may install the reserved parameter.
//! Contracts, callbacks, user executors and later transactions cannot install it.
//! Native replay repeats this original installation; executor reconciliation preserves
//! the reserved slot and the final genesis seal compares it to the original source.
//!
//! TODO(E2): consume this committed selection in the complete authenticated ballot
//! adapter with purpose-bound attempts and certificates. Testing selection grants no
//! production qualification, SCCP or enactment authority.

use super::{StateBlock, StateReadOnly, StateTransaction, WorldReadOnly};
use crate::execution_attempt::{
    ExecutionAttemptError, genesis_read_attempt_error, json_decode_attempt_error,
    norito_decode_attempt_error,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::AccountId,
    block::SignedBlock,
    governance::anonymous_ballot::{
        AnonymousBallotCodecErrorV1, AuthenticatedParliamentCandidateTestingV1,
        ParliamentCandidateTestingErrorV1, ParliamentCandidateTestingPolicyV1,
    },
    isi::{InstructionBox, SetParameter, error::InstructionExecutionError},
    parameter::{CustomParameter, Parameter},
    transaction::{Executable, SignedTransaction},
};

/// Original codec refusals retain local retry authority before error diagnostics.
pub(crate) fn candidate_policy_attempt_error(
    error: ParliamentCandidateTestingErrorV1,
) -> ExecutionAttemptError<&'static str> {
    const INVALID: &str = "Network genesis has no authenticated original candidate policy";
    match error {
        ParliamentCandidateTestingErrorV1::Genesis(error) => genesis_read_attempt_error(
            error,
            |_| "Network genesis has no authenticated original authority",
        ),
        ParliamentCandidateTestingErrorV1::Json(error) => {
            json_decode_attempt_error(error, |_| INVALID)
        }
        ParliamentCandidateTestingErrorV1::Encoding(error) => {
            norito_decode_attempt_error(error, |_| INVALID)
        }
        ParliamentCandidateTestingErrorV1::Codec(
            AnonymousBallotCodecErrorV1::DecodeUnavailable(original),
        ) => ExecutionAttemptError::Deferred(original.into()),
        _ => ExecutionAttemptError::Rejected(INVALID),
    }
}

/// A transient exact native frame, never serialized or reconstructed from a World flag.
pub(super) struct DirectCandidateTesting {
    selection: AuthenticatedParliamentCandidateTestingV1,
    signed_hash: HashOf<SignedTransaction>,
    parameter: CustomParameter,
    authority: AccountId,
}

impl StateTransaction<'_, '_> {
    /// Arm only the original explicit instruction at its authenticated source coordinate.
    pub(crate) fn arm_direct_parliament_candidate_testing(
        &mut self,
        signed: &SignedTransaction,
        authority: &AccountId,
        instruction: &InstructionBox,
        instruction_index: usize,
        direct: bool,
    ) {
        self.clear_direct_parliament_candidate_testing();
        if !direct || self.execution_callback_active() || signed.authority() != authority {
            return;
        }
        let Some(selection) = self
            .genesis_execution_scope
            .as_ref()
            .and_then(|scope| scope.candidate_testing(self))
        else {
            return;
        };
        if selection.source_position().1 != instruction_index
            || self.current_tx_hash != Some(signed.hash())
            || self.tx_call_hash != Some(Hash::from(signed.hash_as_entrypoint()))
            || selection.source_entrypoint_hash() != signed.hash_as_entrypoint()
        {
            return;
        }
        let Executable::Instructions(originals) = signed.instructions() else {
            return;
        };
        if originals.get(instruction_index) != Some(instruction) {
            return;
        }
        let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
            return;
        };
        let Parameter::Custom(parameter) = set.inner() else {
            return;
        };
        if parameter.id() != ParliamentCandidateTestingPolicyV1::parameter_id() {
            return;
        }
        // Original authenticated extraction already bounded and decoded this exact value.
        self.direct_parliament_candidate_testing = Some(DirectCandidateTesting {
            selection,
            signed_hash: signed.hash(),
            parameter: parameter.clone(),
            authority: authority.clone(),
        });
    }

    /// Remove direct authority before entering any user executor, contract or callback.
    pub(crate) fn clear_direct_parliament_candidate_testing(&mut self) {
        self.direct_parliament_candidate_testing = None;
    }

    /// Consume the exact direct marker before the parameter handler can perform any effect.
    pub(crate) fn consume_parliament_candidate_testing_parameter(
        &mut self,
        parameter: &Parameter,
        authority: &AccountId,
    ) -> Result<(), InstructionExecutionError> {
        let Parameter::Custom(parameter) = parameter else {
            return Ok(());
        };
        if parameter.id() != ParliamentCandidateTestingPolicyV1::parameter_id() {
            return Ok(());
        }
        let original = self.direct_parliament_candidate_testing.take();
        let scope_selection = self
            .genesis_execution_scope
            .as_ref()
            .and_then(|scope| scope.candidate_testing(self));
        if let Some(scope) = self.genesis_execution_scope.as_mut() {
            scope.clear_candidate_testing();
        }
        if self.execution_callback_active()
            || self
                .world
                .parameters
                .get()
                .custom()
                .contains_key(parameter.id())
            || !original.is_some_and(|original| {
                original.parameter == *parameter
                    && original.authority == *authority
                    && self.current_tx_hash == Some(original.signed_hash)
                    && self.tx_call_hash
                        == Some(Hash::from(original.selection.source_entrypoint_hash()))
                    && scope_selection.is_some_and(|selection| {
                        selection.network_id() == original.selection.network_id()
                            && selection.source_position() == original.selection.source_position()
                            && selection.source_entrypoint_hash()
                                == original.selection.source_entrypoint_hash()
                            && selection.policy() == original.selection.policy()
                    })
            })
        {
            return Err(InstructionExecutionError::InvariantViolation(
                "candidate testing requires its original one-use direct genesis instruction".into(),
            ));
        }
        Ok(())
    }
}

/// Require the sealed genesis output to reproduce exactly the optional original slot.
/// Comparison uses original canonical values and introduces no second decoder.
pub(crate) fn validate_genesis_output(
    original: &SignedBlock,
    state: &StateBlock<'_>,
) -> Result<(), &'static str> {
    let id = ParliamentCandidateTestingPolicyV1::parameter_id();
    let mut parameters = original
        .external_transactions()
        .filter_map(|transaction| match transaction.instructions() {
            Executable::Instructions(instructions) => Some(instructions),
            _ => None,
        })
        .flat_map(|instructions| instructions.iter())
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set| match set.inner() {
            Parameter::Custom(parameter) if parameter.id() == id => Some(parameter),
            _ => None,
        });
    let parameter = parameters.next();
    if parameters.next().is_some() || state.world().parameters().custom().get(id) != parameter {
        return Err("genesis must execute exactly its original optional candidate-testing policy");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
