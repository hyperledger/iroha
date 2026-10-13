//! SCCP v1 core: state access, the block hook, admission and native SCCP instructions
//! (`specs/sccp.md` §4).
//!
//! The [`Execute`] implementations below delegate each v1 instruction to exactly one entry
//! point. The modules, by the workstream that owns them:
//!
//! | Modules | Owner |
//! |---|---|
//! | [`init`], [`params`], [`admission`], [`fees`] | ws31 (inbound eligibility arms: ws41) |
//! | [`hook`], [`commitment`] | ws30 |
//! | [`outbound`], [`escrow`], [`recipients`] | ws32 |
//! | [`registry`], [`governance`], [`controls`], [`light_clients`] (Parliament half) | ws33 |
//! | [`light_clients`] (advance half), [`inbound`], [`settle`], [`voids`], [`self_claim`] | ws41 |
//! | [`read`] (views served by Torii) | ws35 |
//! | [`parliament_iface`] (the one seam to Parliament-owned functions; stubs today) | WP-S5, WP-S9 |
//!
//! With SCCP absent (no `sccp_parameters`), the hook is a no-op and admission classifies no
//! transaction as SCCP-exempt, so block production and queue behavior are unchanged.

pub mod admission;
pub mod anchor_record;
pub mod anchor_storage;
pub mod anchors;
pub mod commitment;
pub mod committee_storage;
pub mod controls;
pub(crate) mod eligibility;
pub mod escrow;
pub mod fees;
pub mod forgery;
pub mod generation_record;
pub(super) mod generations;
pub mod governance;
pub(crate) mod governance_clock;
pub mod height;
pub mod hold;
pub mod hook;
pub mod inbound;
pub mod init;
pub mod keepalive;
pub mod leaves;
pub(crate) mod liability;
pub mod light_clients;
pub(crate) mod original_read;
pub mod outbound;
pub mod params;
mod pruning;
pub mod parliament_iface;
pub(crate) mod pause_lifecycle;
pub mod pause_record;
pub mod read;
pub mod recipients;
pub mod reconciliation_store;
pub mod reconciliation;
pub mod registry;
pub mod self_claim;
pub mod settle;
pub mod store;
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
            AdvanceSccpLightClientV1, InitializeSccpV1, RecordSccpMessage, ProveSccpForgedMintV1,
            ReportSccpLightClientEquivocationV1, SettleSccpV1, SubmitSccpForgeryEvidenceV1,
            SubmitSccpInboundMessageV1, SubmitSccpOutboundVoidV1,
        },
    },
};

/// Return whether `instruction` is a canonical SCCP v1 instruction.
///
/// Every SCCP instruction routes to the universal dataspace (§4.19) and is admitted by the
/// Initial executor because core enforces every SCCP rule.
#[must_use]
pub fn is_sccp_instruction(instruction: &dyn Instruction) -> bool {
    let any = instruction.as_any();
    any.is::<InitializeSccpV1>()
        || any.is::<iroha_data_model::isi::chain::Keepalive>()
        || any.is::<RecordSccpMessage>()
        || any.is::<SubmitSccpInboundMessageV1>()
        || any.is::<SettleSccpV1>()
        || any.is::<SubmitSccpForgeryEvidenceV1>()
        || any.is::<SubmitSccpOutboundVoidV1>()
        || any.is::<ProveSccpForgedMintV1>()
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
    iroha_data_model::isi::chain::Keepalive => keepalive::execute,
    InitializeSccpV1 => init::execute_initialize,
    RecordSccpMessage => outbound::execute_record,
    SubmitSccpInboundMessageV1 => inbound::execute_submit_inbound,
    SettleSccpV1 => settle::execute_settle,
    SubmitSccpOutboundVoidV1 => voids::execute_submit_void,
    ProveSccpForgedMintV1 => reconciliation::execute_prove,
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
        assert_eq!(SampleInstructions::all().len(), 9);
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

// Execution is one-shot and cannot be authorized by an IVM or callback instruction.
impl Execute for SubmitSccpForgeryEvidenceV1 {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        state_transaction.consume_direct_sccp_forgery(&self)?;
        forgery::execute_forgery(&self, state_transaction)
            .map_err(|error| error.into_instruction_error(state_transaction))
    }
}

#[cfg(test)]
mod parameter_mutation_tests;
