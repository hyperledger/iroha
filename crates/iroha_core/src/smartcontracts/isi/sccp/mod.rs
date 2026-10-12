//! SCCP v1 execution: native Sumeragi finality, committee generations and message state.
//!
//! Each current instruction delegates to one Core entry point. SCCP committee keys come
//! from the authenticated consensus schedule; no separate attestation-key or signing
//! protocol participates in execution.
//!
//! With SCCP absent, admission classifies no transaction as SCCP-exempt. The finalizer
//! returns the canonical inactive header and leaves SCCP state untouched.
//!
//! TODO: complete native forgery evidence, shared keepalive and certified read bundles in
//! the coordinated shared-model migration before qualifying SCCP routes for release.

pub mod admission;
pub mod anchors;
pub mod commitment;
pub mod context;
pub mod controls;
pub mod escrow;
pub mod fees;
pub mod forgery;
pub mod generation;
pub mod governance;
pub mod height;
mod holds;
pub mod hook;
pub mod inbound;
pub mod init;
pub mod leaves;
pub(crate) mod liability;
pub mod light_clients;
pub mod outbound;
pub mod params;
pub mod prune;
pub mod read;
pub mod recipients;
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
            AdvanceSccpLightClientV1, InitializeSccpV1, RecordSccpMessage,
            ReportSccpLightClientEquivocationV1, SettleSccpV1, SubmitSccpForgeryEvidenceV1,
            SubmitSccpInboundMessageV1, SubmitSccpOutboundVoidV1,
        },
    },
};

/// Return whether `instruction` is a current SCCP v1 instruction.
///
/// Every SCCP instruction routes to the universal dataspace (§4.19) and is admitted by the
/// Initial executor because core enforces every SCCP rule.
#[must_use]
pub fn is_sccp_instruction(instruction: &dyn Instruction) -> bool {
    let any = instruction.as_any();
    any.is::<InitializeSccpV1>()
        || any.is::<RecordSccpMessage>()
        || any.is::<SubmitSccpInboundMessageV1>()
        || any.is::<SettleSccpV1>()
        || any.is::<SubmitSccpOutboundVoidV1>()
        || any.is::<SubmitSccpForgeryEvidenceV1>()
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

#[cfg(test)]
mod parameter_mutation_tests;

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
