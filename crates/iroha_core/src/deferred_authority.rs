//! Signed committee, monetary staking and SCCP outbound authority across opaque execution
//! boundaries.
//!
//! Validator committee preparation commands, monetary staking plans and outbound SCCP records
//! (`RecordSccpMessage`, `specs/sccp.md` §4.4) must be signed instructions. An opaque deferred
//! executable (a trigger body, an IVM or contract output, an IVM-proved overlay, or a multisig
//! approval that such an executable derives) may not derive them. A multisig proposal is not
//! opaque when signed transactions approve it: its instructions execute inside the signed
//! approval, so a quorum-approved `RecordSccpMessage` records from the multisig account. This
//! authority check is independent of native fee accounting and runs before any deferred group
//! executes.

use crate::{
    execution_attempt::ExecutionAttemptError as Attempt,
    smartcontracts::isi::multisig::{
        live_proposal_instructions_for_approval, multisig_instruction_decode_attempt,
    },
    state::StateTransaction,
    tx::TransactionRejectionReason,
};
use core::fmt;
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    isi::{InstructionBox, RegisterBox, SetParameter, sccp::RecordSccpMessage},
    parameter::Parameter,
    transaction::{Executable, ExecutableBatchItem},
};
use iroha_executor_data_model::isi::multisig::{MultisigApprove, MultisigInstructionBox};

/// Maximum nested proposal/trigger depth traversed for one deferred group.
const MAX_OPAQUE_DEFERRED_PROPOSAL_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpaqueDeferredAuthorityError {
    CommitteeOperation {
        instruction_index: usize,
    },
    StakingOperation {
        instruction_index: usize,
        instruction_wire_id: &'static str,
    },
    SccpOutboundRecord {
        instruction_index: usize,
    },
    UnresolvedMultisigApproval {
        account_id: String,
        instructions_hash_hex: String,
    },
    ProposalDepthExceeded,
    ProposalReadFailed(String),
}

impl fmt::Display for OpaqueDeferredAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitteeOperation { instruction_index } => write!(
                f,
                "opaque deferred executable derived a validator committee operation at instruction {instruction_index}; the complete preparation command must be a signed instruction"
            ),
            Self::StakingOperation {
                instruction_index,
                instruction_wire_id,
            } => write!(
                f,
                "opaque deferred executable derived monetary staking operation `{instruction_wire_id}` at instruction {instruction_index}; the exact monetary plan must be a signed instruction"
            ),
            Self::SccpOutboundRecord { instruction_index } => write!(
                f,
                "opaque deferred executable derived `RecordSccpMessage` at instruction {instruction_index}; an outbound SCCP record must be a signed transaction instruction or an instruction of a multisig proposal approved by signed transactions"
            ),
            Self::UnresolvedMultisigApproval {
                account_id,
                instructions_hash_hex,
            } => write!(
                f,
                "opaque deferred executable contains a multisig approval that cannot be resolved before execution for account {account_id} and instructions hash {instructions_hash_hex}"
            ),
            Self::ProposalDepthExceeded => write!(
                f,
                "opaque deferred proposal graph exceeds the maximum traversal depth"
            ),
            Self::ProposalReadFailed(reason) => {
                write!(f, "live multisig proposal read failed: {reason}")
            }
        }
    }
}

/// Reject committee preparation, monetary staking and SCCP outbound records derived by opaque
/// deferred groups.
///
/// Deferred multisig approvals are resolved against this execution overlay, so a live
/// proposal cannot smuggle a command that its signers never reviewed as an instruction.
///
/// # Errors
/// Any nested committee, monetary staking or `RecordSccpMessage` instruction, an unresolved
/// approval, or an excessively deep proposal graph.
pub(crate) fn reject_opaque_deferred_authority(
    instruction_groups: &std::collections::BTreeMap<AccountId, Vec<InstructionBox>>,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Attempt<TransactionRejectionReason>> {
    reject_opaque_instruction_authority(
        instruction_groups
            .values()
            .flat_map(|instructions| instructions.iter()),
        state_transaction,
    )
    .map_err(|error| error.map_rejection(TransactionRejectionReason::Validation))
}

/// Validate the actual effects produced by an opaque host or verified replay.
///
/// Borrow the original ordered effects so every consumption boundary applies the
/// same recursive signed-plan rule before executing its first instruction.
///
/// # Errors
/// Rejects nested committee, monetary staking or `RecordSccpMessage` instructions,
/// unresolved live multisig approvals, and proposal graphs exceeding the traversal bound.
#[expect(
    single_use_lifetimes,
    reason = "Rust 1.93 requires a named lifetime for reference items in impl IntoIterator bounds"
)]
pub(crate) fn reject_opaque_instruction_authority<'a>(
    instructions: impl IntoIterator<Item = &'a InstructionBox>,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Attempt<ValidationFail>> {
    if cfg!(all(test, sumeragi_core_mutation = "HC66")) {
        return Ok(());
    }
    let mut visited = std::collections::BTreeSet::new();
    reject_opaque_committee_operations_with(instructions, &mut visited, 0, &mut |approve| {
        live_proposal_instructions_for_approval(state_transaction, approve)
    })
    .map_err(|error| {
        error.map_rejection(|error| {
            ValidationFail::NotPermitted(format!(
                "deferred execution authority rejected transaction: {error}"
            ))
        })
    })
}

/// Monetary staking instructions whose exact plan must be signed.
fn monetary_staking_wire_id(instruction: &InstructionBox) -> Option<&'static str> {
    use iroha_data_model::isi::staking::{
        BondPublicLaneStake, ClaimPublicLaneRewards, FinalizePublicLaneUnbond,
        RegisterPublicLaneCandidate, RegisterPublicLaneValidator, SlashPublicLaneValidator,
    };
    macro_rules! classify {
        ($($ty:ty),+ $(,)?) => {$(
            if instruction.as_any().downcast_ref::<$ty>().is_some() {
                return iroha_data_model::isi::instruction_wire_id(instruction);
            }
        )+};
    }
    classify!(
        RegisterPublicLaneCandidate,
        RegisterPublicLaneValidator,
        BondPublicLaneStake,
        FinalizePublicLaneUnbond,
        SlashPublicLaneValidator,
        ClaimPublicLaneRewards,
    );
    None
}

fn reject_opaque_committee_operation(
    instruction: &InstructionBox,
    instruction_index: usize,
) -> Result<(), OpaqueDeferredAuthorityError> {
    if instruction
        .as_any()
        .downcast_ref::<SetParameter>()
        .is_some_and(|set| {
            matches!(set.inner(), Parameter::Custom(custom)
                if custom.id() == &iroha_data_model::nexus::ValidatorCommitteeOperationV1::parameter_id())
        })
    {
        // Match the reserved identifier before decoding: malformed commands may
        // not evade the signed-envelope requirement by failing deserialization.
        return Err(OpaqueDeferredAuthorityError::CommitteeOperation { instruction_index });
    }
    if let Some(instruction_wire_id) = monetary_staking_wire_id(instruction) {
        return Err(OpaqueDeferredAuthorityError::StakingOperation {
            instruction_index,
            instruction_wire_id,
        });
    }
    if is_sccp_outbound_record(instruction) {
        return Err(OpaqueDeferredAuthorityError::SccpOutboundRecord { instruction_index });
    }
    Ok(())
}

/// Return whether `instruction` is the value-moving outbound SCCP record (`specs/sccp.md` §4.4).
fn is_sccp_outbound_record(instruction: &InstructionBox) -> bool {
    instruction
        .as_any()
        .downcast_ref::<RecordSccpMessage>()
        .is_some()
}

/// Return whether registering `executable` as a trigger action would derive `RecordSccpMessage`.
///
/// This is the static, state-free part of the signed-only rule (`specs/sccp.md` §4.4): it finds
/// the record directly in the action's instructions, IVM-proved overlay or batch, in a trigger
/// those instructions register, and in a multisig proposal they create. Trigger registration and
/// the IVM `CREATE_TRIGGER` syscall refuse such an action before it is stored or queued. A live
/// multisig approval needs ledger state to resolve; the execution-time check
/// ([`reject_opaque_instruction_authority`]) covers it. Graphs deeper than the traversal bound
/// return `false` here and are refused by that check.
pub(crate) fn trigger_executable_derives_sccp_outbound_record(executable: &Executable) -> bool {
    executable_derives_sccp_outbound_record(executable, 0)
}

fn executable_derives_sccp_outbound_record(executable: &Executable, depth: usize) -> bool {
    match executable {
        Executable::Instructions(instructions) => {
            instructions_derive_sccp_outbound_record(instructions.iter(), depth)
        }
        Executable::IvmProved(proved) => {
            instructions_derive_sccp_outbound_record(proved.overlay.iter(), depth)
        }
        Executable::Batch(items) => instructions_derive_sccp_outbound_record(
            items.iter().filter_map(|item| match item {
                ExecutableBatchItem::Instruction(instruction) => Some(instruction),
                ExecutableBatchItem::ContractCall(_) => None,
            }),
            depth,
        ),
        // Contract and raw IVM outputs are checked when the host's effects are consumed.
        Executable::ContractCall(_) | Executable::Ivm(_) => false,
    }
}

#[expect(
    single_use_lifetimes,
    reason = "Rust 1.93 requires a named lifetime for reference items in impl IntoIterator bounds"
)]
fn instructions_derive_sccp_outbound_record<'a>(
    instructions: impl IntoIterator<Item = &'a InstructionBox>,
    depth: usize,
) -> bool {
    if depth > MAX_OPAQUE_DEFERRED_PROPOSAL_DEPTH {
        return false;
    }
    instructions.into_iter().any(|instruction| {
        if is_sccp_outbound_record(instruction) {
            return true;
        }
        if let Ok(MultisigInstructionBox::Propose(proposal)) =
            MultisigInstructionBox::try_from(instruction)
            && instructions_derive_sccp_outbound_record(proposal.instructions.iter(), depth + 1)
        {
            return true;
        }
        matches!(
            instruction.as_any().downcast_ref::<RegisterBox>(),
            Some(RegisterBox::Trigger(register))
                if executable_derives_sccp_outbound_record(
                    register.object.action().executable(),
                    depth + 1,
                )
        )
    })
}

#[expect(
    single_use_lifetimes,
    reason = "Rust 1.93 requires a named lifetime for reference items in impl IntoIterator bounds"
)]
fn reject_opaque_committee_operations_with<'a, F>(
    instructions: impl IntoIterator<Item = &'a InstructionBox>,
    visited: &mut std::collections::BTreeSet<String>,
    depth: usize,
    resolve: &mut F,
) -> Result<(), Attempt<OpaqueDeferredAuthorityError>>
where
    F: FnMut(
        &MultisigApprove,
    ) -> Result<Option<(AccountId, Vec<InstructionBox>)>, Attempt<ValidationFail>>,
{
    if depth > MAX_OPAQUE_DEFERRED_PROPOSAL_DEPTH {
        return Err(OpaqueDeferredAuthorityError::ProposalDepthExceeded.into());
    }
    for (index, instruction) in instructions.into_iter().enumerate() {
        reject_opaque_committee_operation(instruction, index)?;
        let multisig = match MultisigInstructionBox::try_from(instruction) {
            Ok(multisig) => Some(multisig),
            Err(error) => match multisig_instruction_decode_attempt(error, |_| ()) {
                Attempt::Deferred(reason) => return Err(Attempt::Deferred(reason)),
                Attempt::Rejected(()) => None,
            },
        };
        if let Some(multisig) = multisig {
            match multisig {
                MultisigInstructionBox::Propose(proposal) => {
                    reject_opaque_committee_operations_with(
                        proposal.instructions.iter(),
                        visited,
                        depth + 1,
                        resolve,
                    )?;
                }
                MultisigInstructionBox::Approve(approval) => {
                    let Some((authority, instructions)) = resolve(&approval).map_err(|error| {
                        error.map_rejection(|error| {
                            OpaqueDeferredAuthorityError::ProposalReadFailed(error.to_string())
                        })
                    })?
                    else {
                        return Err(OpaqueDeferredAuthorityError::UnresolvedMultisigApproval {
                            account_id: approval.account.to_string(),
                            instructions_hash_hex: hex::encode(approval.instructions_hash.as_ref()),
                        }
                        .into());
                    };
                    let identity = format!(
                        "{}:{}",
                        authority,
                        hex::encode(approval.instructions_hash.as_ref())
                    );
                    if visited.insert(identity) {
                        reject_opaque_committee_operations_with(
                            instructions.iter(),
                            visited,
                            depth + 1,
                            resolve,
                        )?;
                    }
                }
                MultisigInstructionBox::Register(_)
                | MultisigInstructionBox::Cancel(_)
                | MultisigInstructionBox::InvalidateOutstanding(_) => {}
            }
        }
        let Some(RegisterBox::Trigger(register)) =
            instruction.as_any().downcast_ref::<RegisterBox>()
        else {
            continue;
        };
        match register.object.action().executable() {
            Executable::Instructions(nested) => {
                reject_opaque_committee_operations_with(
                    nested.iter(),
                    visited,
                    depth + 1,
                    resolve,
                )?;
            }
            Executable::IvmProved(proved) => {
                reject_opaque_committee_operations_with(
                    proved.overlay.iter(),
                    visited,
                    depth + 1,
                    resolve,
                )?;
            }
            Executable::Batch(items) => {
                for item in items {
                    if let ExecutableBatchItem::Instruction(instruction) = item {
                        reject_opaque_committee_operations_with(
                            std::slice::from_ref(instruction),
                            visited,
                            depth + 1,
                            resolve,
                        )?;
                    }
                }
            }
            Executable::ContractCall(_) | Executable::Ivm(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::isi::staking::{
        BondPublicLaneStake, ClaimPublicLaneRewards, FinalizePublicLaneUnbond,
        RegisterPublicLaneCandidate, RegisterPublicLaneValidator, SlashPublicLaneValidator,
    };

    #[test]
    fn staking_wire_ids_match_the_canonical_registry() {
        let registry = iroha_data_model::instruction_registry::default();
        macro_rules! check {
            ($($ty:ty => $wire_id:literal),+ $(,)?) => {$(
                assert_eq!(registry.wire_id(core::any::type_name::<$ty>()), Some($wire_id));
            )+};
        }
        check!(
            RegisterPublicLaneCandidate => "iroha.staking.register_public_lane_candidate",
            RegisterPublicLaneValidator => "iroha.instruction.v1::staking::RegisterPublicLaneValidator",
            BondPublicLaneStake => "iroha.instruction.v1::staking::BondPublicLaneStake",
            FinalizePublicLaneUnbond => "iroha.instruction.v1::staking::FinalizePublicLaneUnbond",
            SlashPublicLaneValidator => "iroha.instruction.v1::staking::SlashPublicLaneValidator",
            ClaimPublicLaneRewards => "iroha.instruction.v1::staking::ClaimPublicLaneRewards",
        );
    }

    fn sccp_record() -> InstructionBox {
        crate::smartcontracts::isi::sccp::test_support::SampleInstructions::record().into()
    }

    fn log(message: &str) -> InstructionBox {
        iroha_data_model::isi::Log::new(iroha_data_model::Level::INFO, message.to_owned()).into()
    }

    fn register_by_call_trigger(name: &str, instructions: Vec<InstructionBox>) -> InstructionBox {
        use iroha_data_model::{
            events::execute_trigger::ExecuteTriggerEventFilter,
            isi::Register,
            trigger::{
                Trigger, TriggerId,
                action::{Action, Repeats},
            },
        };
        let authority = iroha_test_samples::ALICE_ID.clone();
        let id: TriggerId = name.parse().expect("trigger id");
        let action = Action::new(
            instructions,
            Repeats::Exactly(1),
            authority.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(id.clone())
                .under_authority(authority),
        )
        .expect("by-call trigger action");
        Register::trigger(Trigger::new(id, action)).into()
    }

    fn propose(instructions: Vec<InstructionBox>) -> InstructionBox {
        iroha_executor_data_model::isi::multisig::MultisigPropose::new(
            iroha_test_samples::ALICE_ID.clone(),
            instructions,
            None,
        )
        .into()
    }

    fn check(
        instructions: &[InstructionBox],
        proposal: Option<Vec<InstructionBox>>,
    ) -> Result<(), Attempt<OpaqueDeferredAuthorityError>> {
        reject_opaque_committee_operations_with(
            instructions,
            &mut std::collections::BTreeSet::new(),
            0,
            &mut |_| {
                Ok(proposal
                    .clone()
                    .map(|body| (iroha_test_samples::ALICE_ID.clone(), body)))
            },
        )
    }

    #[test]
    fn opaque_sccp_outbound_record_requires_a_signed_instruction() {
        let refused = |instruction_index| {
            Err(OpaqueDeferredAuthorityError::SccpOutboundRecord { instruction_index }.into())
        };
        // Directly derived (a trigger body, contract output or proved overlay).
        assert_eq!(check(&[log("first"), sccp_record()], None), refused(1));
        // In a trigger that the opaque group registers.
        assert_eq!(
            check(
                &[register_by_call_trigger(
                    "nested_record",
                    vec![log("a"), sccp_record()]
                )],
                None,
            ),
            refused(1)
        );
        // In a multisig proposal that the opaque group creates.
        assert_eq!(check(&[propose(vec![sccp_record()])], None), refused(0));
        // In a live proposal that an opaque multisig approval would execute.
        let approval: InstructionBox = MultisigApprove::new(
            iroha_test_samples::ALICE_ID.clone(),
            iroha_crypto::HashOf::new(&vec![sccp_record()]),
        )
        .into();
        assert_eq!(
            check(core::slice::from_ref(&approval), Some(vec![sccp_record()])),
            refused(0)
        );
        // The same approval of an ordinary proposal and every other SCCP instruction pass.
        assert_eq!(check(&[approval], Some(vec![log("ordinary")])), Ok(()));
        let others: Vec<InstructionBox> =
            crate::smartcontracts::isi::sccp::test_support::SampleInstructions::all()
                .into_iter()
                .filter(|instruction| !is_sccp_outbound_record(instruction))
                .collect();
        assert_eq!(others.len(), 9);
        assert_eq!(check(&others, None), Ok(()));
        assert!(
            OpaqueDeferredAuthorityError::SccpOutboundRecord {
                instruction_index: 3
            }
            .to_string()
            .contains("derived `RecordSccpMessage` at instruction 3; an outbound SCCP record must be a signed transaction instruction")
        );
    }

    #[test]
    fn trigger_registration_scan_finds_nested_sccp_outbound_records() {
        use iroha_data_model::transaction::{IvmBytecode, IvmProved};
        let derives =
            |executable: Executable| trigger_executable_derives_sccp_outbound_record(&executable);
        assert!(derives(Executable::Instructions(
            vec![sccp_record()].into()
        )));
        assert!(!derives(Executable::Instructions(
            vec![log("plain")].into()
        )));
        assert!(derives(Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(log("first")),
                ExecutableBatchItem::Instruction(sccp_record()),
            ]
            .into()
        )));
        assert!(derives(Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(Vec::new()),
            overlay: vec![sccp_record()].into(),
            events_commitment: iroha_crypto::Hash::new(b"events"),
            gas_policy_commitment: iroha_crypto::Hash::new(b"gas"),
        })));
        assert!(derives(Executable::Instructions(
            vec![register_by_call_trigger("inner", vec![sccp_record()])].into()
        )));
        assert!(derives(Executable::Instructions(
            vec![propose(vec![sccp_record()])].into()
        )));
        // An approval needs live state; the execution-time check resolves it.
        let approval: InstructionBox = MultisigApprove::new(
            iroha_test_samples::ALICE_ID.clone(),
            iroha_crypto::HashOf::new(&vec![sccp_record()]),
        )
        .into();
        assert!(!derives(Executable::Instructions(vec![approval].into())));
        assert!(!derives(Executable::Ivm(IvmBytecode::from_compiled(
            Vec::new()
        ))));
        // Other SCCP instructions are not signed-only.
        let others: Vec<InstructionBox> =
            crate::smartcontracts::isi::sccp::test_support::SampleInstructions::all()
                .into_iter()
                .filter(|instruction| !is_sccp_outbound_record(instruction))
                .collect();
        assert!(!derives(Executable::Instructions(others.into())));
        // Beyond the traversal bound the scan stops; execution refuses the depth instead.
        let mut nested = vec![sccp_record()];
        for depth in 0..=MAX_OPAQUE_DEFERRED_PROPOSAL_DEPTH {
            nested = vec![register_by_call_trigger(&format!("depth_{depth}"), nested)];
        }
        assert!(!derives(Executable::Instructions(nested.into())));
    }
}
