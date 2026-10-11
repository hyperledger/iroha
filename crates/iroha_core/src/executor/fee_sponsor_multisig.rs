//! Exact enrolled-controller sponsorship for canonical native contract proposals.

use super::*;
use crate::execution_attempt::{ExecutionAttemptError as Attempt, json_decode_attempt_error};
use crate::smartcontracts::isi::multisig::{
    fee_proposal_key_is_unused, multisig_instruction_decode_attempt, read_pending_fee_proposal,
    read_registered_account_state, read_settled_fee_proposal,
};
use iroha_crypto::HashOf;
use iroha_data_model::nexus::FeeSponsorContractSelector;
use iroha_data_model::smart_contract::multisig_call::{
    MultisigContractCallRecognitionError, recognize_multisig_contract_call,
};
use std::borrow::Cow;

/// Admission observes pending state; settlement may use only this entrypoint's proven execution.
#[derive(Clone, Copy)]
pub(super) struct RuleContext {
    observation_time_ms: u64,
    settlement: Option<SettlementContext>,
}

#[derive(Clone, Copy)]
struct SettlementContext {
    entrypoint_hash: Option<[u8; Hash::LENGTH]>,
    block_height: u64,
}

impl RuleContext {
    pub(super) fn admission(observation_time_ms: u64) -> Self {
        Self {
            observation_time_ms,
            settlement: None,
        }
    }

    pub(super) fn settlement(
        observation_time_ms: u64,
        entrypoint_hash: Option<[u8; Hash::LENGTH]>,
        block_height: u64,
    ) -> Self {
        Self {
            observation_time_ms,
            settlement: Some(SettlementContext {
                entrypoint_hash,
                block_height,
            }),
        }
    }
}

fn invalid(message: impl Into<String>) -> NexusFeeAdmissionError {
    NexusFeeAdmissionError::sponsor(FeeRejectionCode::OperationNotAllowed, message)
}

fn map_state_error(error: Attempt<ValidationFail>) -> Attempt<NexusFeeAdmissionError> {
    error.map_rejection(|error| invalid(format!("native sponsored multisig state: {error}")))
}

fn enrolled(
    world: &impl WorldReadOnly,
    program_id: &FeeSponsorProgramId,
    account: &AccountId,
) -> bool {
    let key = FeeSponsorEnrollmentKey {
        program_id: program_id.clone(),
        beneficiary: account.clone(),
    };
    world
        .fee_sponsor_enrollments()
        .get(&key)
        .is_some_and(|value| value.key == key)
}

fn instruction_at(executable: &Executable, index: usize) -> Option<&InstructionBox> {
    match executable {
        Executable::Instructions(instructions) => instructions.get(index),
        Executable::Batch(items) => match items.get(index)? {
            ExecutableBatchItem::Instruction(instruction) => Some(instruction),
            ExecutableBatchItem::ContractCall(_) => None,
        },
        _ => None,
    }
}

fn decode_multisig(
    instruction: &InstructionBox,
) -> Result<Option<MultisigInstructionBox>, Attempt<NexusFeeAdmissionError>> {
    match MultisigInstructionBox::try_from(instruction) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            match multisig_instruction_decode_attempt(error, |error| invalid(error.to_string())) {
                Attempt::Deferred(reason) => Err(Attempt::Deferred(reason)),
                Attempt::Rejected(_) => Ok(None),
            }
        }
    }
}

fn instruction_hash(
    instructions: &Vec<InstructionBox>,
) -> Result<HashOf<Vec<InstructionBox>>, Attempt<NexusFeeAdmissionError>> {
    HashOf::try_new(instructions).map_err(|error| {
        multisig_instruction_decode_attempt(error, |error| {
            invalid(format!("sponsored multisig instruction hash: {error}"))
        })
    })
}

/// A preceding proposal is authority only for a later approval of this exact target and hash.
fn earlier_proposal(
    payload: &TransactionPayload,
    index: usize,
    target: &AccountId,
    hash: &HashOf<Vec<InstructionBox>>,
) -> Result<Option<Vec<InstructionBox>>, Attempt<NexusFeeAdmissionError>> {
    let mut selected = None;
    for earlier in 0..index {
        let Some(instruction) = instruction_at(&payload.instructions, earlier) else {
            continue;
        };
        let Some(MultisigInstructionBox::Propose(propose)) = decode_multisig(instruction)? else {
            continue;
        };
        if propose.account == *target && instruction_hash(&propose.instructions)? == *hash {
            if selected.is_some() {
                return Err(invalid("duplicate preceding sponsored multisig proposal").into());
            }
            selected = Some(propose.instructions);
        }
    }
    Ok(selected)
}

pub(super) fn selector_matches(
    world: &impl WorldReadOnly,
    program_id: &FeeSponsorProgramId,
    beneficiary: &AccountId,
    selector: &FeeSponsorContractSelector,
    payload: &TransactionPayload,
    index: usize,
    context: RuleContext,
) -> Result<bool, Attempt<NexusFeeAdmissionError>> {
    if beneficiary != &payload.authority {
        return Ok(false);
    }
    if matches!(
        context.settlement,
        Some(SettlementContext {
            entrypoint_hash: None,
            ..
        })
    ) {
        return Ok(false);
    }
    let Some(instruction) = instruction_at(&payload.instructions, index) else {
        return Ok(false);
    };
    let Some(multisig) = decode_multisig(instruction)? else {
        return Ok(false);
    };
    let (target, instructions, same_envelope) = match &multisig {
        MultisigInstructionBox::Propose(propose) => (
            &propose.account,
            Cow::Borrowed(propose.instructions.as_slice()),
            true,
        ),
        MultisigInstructionBox::Approve(approve) => {
            if let Some(instructions) =
                earlier_proposal(payload, index, &approve.account, &approve.instructions_hash)?
            {
                (&approve.account, Cow::Owned(instructions), true)
            } else {
                let pending = read_pending_fee_proposal(
                    world,
                    &approve.account,
                    &approve.instructions_hash,
                    context.observation_time_ms,
                )
                .map_err(map_state_error)?;
                let instructions = match (pending, context.settlement) {
                    (Some(instructions), _) => instructions,
                    (
                        None,
                        Some(SettlementContext {
                            entrypoint_hash: Some(hash),
                            block_height,
                        }),
                    ) => {
                        let Some(instructions) = read_settled_fee_proposal(
                            world,
                            &approve.account,
                            &approve.instructions_hash,
                            hash,
                            block_height,
                        )
                        .map_err(map_state_error)?
                        else {
                            return Ok(false);
                        };
                        instructions
                    }
                    (None, _) => return Ok(false),
                };
                (&approve.account, Cow::Owned(instructions), false)
            }
        }
        _ => return Ok(false),
    };
    if same_envelope && context.settlement.is_none() {
        let hash = match &multisig {
            MultisigInstructionBox::Propose(propose) => instruction_hash(&propose.instructions)?,
            MultisigInstructionBox::Approve(approve) => approve.instructions_hash,
            _ => return Ok(false),
        };
        // A new sponsorship admission requires a fresh proposal key. Existing
        // expired, terminal or malformed rows cannot sponsor the same intent again.
        if !fee_proposal_key_is_unused(world, target, &hash) {
            return Ok(false);
        }
    }
    // Enrollment is explicit for both identities even when the revision permits route-default beneficiaries.
    if !enrolled(world, program_id, beneficiary)
        || !enrolled(world, program_id, target)
        || read_registered_account_state(world, target)
            .map_err(map_state_error)?
            .is_none()
    {
        return Ok(false);
    }
    let recognized = recognize_multisig_contract_call(target, instructions.as_ref()).map_err(
        |error| match error {
            MultisigContractCallRecognitionError::Json(error) => {
                json_decode_attempt_error(error, |error| invalid(error.to_string()))
            }
            MultisigContractCallRecognitionError::Encoding(error) => {
                multisig_instruction_decode_attempt(error, |error| invalid(error.to_string()))
            }
        },
    )?;
    let Some(recognized) = recognized else {
        return Ok(false);
    };
    if same_envelope && recognized.attempt_created_at_ms.get() != payload.creation_time_ms {
        return Ok(false);
    }
    let call = recognized.invocation;
    Ok(selector.contract_address == call.contract_address
        && selector.code_hash == call.expected_code_hash
        && selector.entrypoints.contains(&call.entrypoint)
        && world.contract_aliases().get(&recognized.alias) == Some(&call.contract_address)
        && world.contract_instances().get(&call.contract_address) == Some(&call.expected_code_hash))
}

#[cfg(test)]
#[path = "fee_sponsor_multisig_tests.rs"]
mod tests;
