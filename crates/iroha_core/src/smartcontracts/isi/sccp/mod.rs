//! SCCP v1 core: state access, block hooks, admission and the ten v1 instructions
//! (`specs/sccp.md` §4).
//!
//! The [`Execute`] implementations below delegate each v1 instruction to exactly one entry
//! point. The modules, by the workstream that owns them:
//!
//! | Modules | Owner |
//! |---|---|
//! | [`init`], [`params`], [`bridge_keys`], [`attestations`], [`faults`], [`admission`], [`fees`] | ws31 (inbound eligibility arms: ws41) |
//! | [`hook`], [`roster`], [`commitment`], [`subjects`], [`prune`] | ws30 |
//! | [`outbound`], [`escrow`], [`recipients`] | ws32 |
//! | [`registry`], [`governance`], [`controls`], [`light_clients`] (Parliament half) | ws33 |
//! | [`light_clients`] (advance half), [`inbound`], [`settle`], [`voids`], [`self_claim`] | ws41 |
//! | [`read`] (views and proof bundles served by Torii) | ws35 |
//!
//! With SCCP absent (no `sccp_parameters`), every hook is a no-op and admission classifies no
//! transaction as SCCP-exempt, so block production and queue behavior are unchanged.

pub mod admission;
pub mod attestations;
pub mod bridge_keys;
pub mod commitment;
pub mod controls;
pub mod escrow;
pub mod faults;
pub mod fees;
pub mod governance;
pub mod height;
pub mod hook;
pub mod inbound;
pub mod init;
pub mod leaves;
pub mod light_clients;
pub mod outbound;
pub mod params;
pub mod prune;
pub mod read;
pub mod recipients;
pub mod registry;
pub mod roster;
pub mod self_claim;
pub mod settle;
pub mod store;
pub mod subjects;
pub mod voids;
pub mod witness;

#[cfg(test)]
mod eligibility_tests;
#[cfg(test)]
pub(crate) mod test_support;

use super::Execute;
use crate::state::StateTransaction;
use iroha_data_model::{
    account::AccountId,
    isi::{
        Instruction,
        error::InstructionExecutionError as Error,
        sccp::{
            AdvanceSccpLightClientV1, InitializeSccpV1, RecordSccpMessage,
            ReportSccpLightClientEquivocationV1, SetSccpBridgeKeyV1, SettleSccpV1,
            SubmitSccpAttestationFaultV1, SubmitSccpAttestationsV1, SubmitSccpInboundMessageV1,
            SubmitSccpOutboundVoidV1,
        },
    },
};

/// Return whether `instruction` is one of the ten SCCP v1 instructions.
///
/// Every SCCP instruction routes to the universal dataspace (§4.19) and is admitted by the
/// Initial executor because core enforces every SCCP rule.
#[must_use]
pub fn is_sccp_instruction(instruction: &dyn Instruction) -> bool {
    let any = instruction.as_any();
    any.is::<InitializeSccpV1>()
        || any.is::<SetSccpBridgeKeyV1>()
        || any.is::<SubmitSccpAttestationsV1>()
        || any.is::<SubmitSccpAttestationFaultV1>()
        || any.is::<RecordSccpMessage>()
        || any.is::<SubmitSccpInboundMessageV1>()
        || any.is::<SettleSccpV1>()
        || any.is::<SubmitSccpOutboundVoidV1>()
        || any.is::<AdvanceSccpLightClientV1>()
        || any.is::<ReportSccpLightClientEquivocationV1>()
}

/// Implement [`Execute`] for each instruction by delegating to its single entry point.
macro_rules! delegate_execute {
    ($($instruction:ty => $entry:path),+ $(,)?) => {$(
        impl Execute for $instruction {
            fn execute(
                self,
                authority: &AccountId,
                state_transaction: &mut StateTransaction<'_, '_>,
            ) -> Result<(), Error> {
                $entry(self, authority, state_transaction)
            }
        }
    )+};
}

delegate_execute! {
    InitializeSccpV1 => init::execute_initialize,
    SetSccpBridgeKeyV1 => bridge_keys::execute_set_bridge_key,
    SubmitSccpAttestationsV1 => attestations::execute_submit_attestations,
    SubmitSccpAttestationFaultV1 => faults::execute_submit_fault,
    RecordSccpMessage => outbound::execute_record,
    SubmitSccpInboundMessageV1 => inbound::execute_submit_inbound,
    SettleSccpV1 => settle::execute_settle,
    SubmitSccpOutboundVoidV1 => voids::execute_submit_void,
    AdvanceSccpLightClientV1 => light_clients::execute_advance,
    ReportSccpLightClientEquivocationV1 => light_clients::execute_report_equivocation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        SampleInstructions, authority, blank_state, header,
    };
    use iroha_data_model::isi::InstructionBox;

    #[test]
    fn every_v1_instruction_is_recognized_and_nothing_else_is() {
        for instruction in SampleInstructions::all() {
            assert!(is_sccp_instruction(&*instruction), "{instruction:?}");
        }
        let log = InstructionBox::from(iroha_data_model::isi::Log::new(
            iroha_data_model::Level::INFO,
            "not SCCP".to_owned(),
        ));
        assert!(!is_sccp_instruction(&*log));
    }

    #[test]
    fn every_instruction_fails_closed_without_sccp() {
        // Genesis-only initialization refuses outside genesis; every other instruction refuses
        // on a network without SCCP (or without the record it names).
        let state = blank_state();
        let mut block = state.block(header(2));
        let authority = authority(1);
        for instruction in SampleInstructions::all() {
            let mut stx = block.transaction();
            let error = crate::smartcontracts::isi::execute_borrowed_instruction(
                &instruction,
                &authority,
                &mut stx,
            )
            .expect_err("an SCCP instruction must fail closed without SCCP");
            assert!(
                !format!("{error}").contains("TODO("),
                "{instruction:?}: {error}"
            );
        }
    }
}
