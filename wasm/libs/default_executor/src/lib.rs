//! Iroha default executor.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

extern crate alloc;

use dlmalloc::GlobalDlmalloc;
use iroha_executor::{
    data_model::block::BlockHeader,
    debug::{dbg_panic, DebugExpectExt},
    prelude::*,
    DataModelBuilder,
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

mod multisig;

/// Executor that replaces some of [`Execute`]'s methods with sensible defaults
///
/// # Warning
///
/// The defaults are not guaranteed to be stable.
#[derive(Debug, Clone, Visit, Execute, Entrypoints)]
#[visit(custom(visit_custom_instructions))]
struct Executor {
    host: Iroha,
    context: Context,
    verdict: Result,
}

impl Executor {
    fn ensure_genesis(curr_block: BlockHeader) {
        if !curr_block.is_genesis() {
            dbg_panic(
                "Default Executor is intended to be used only in genesis. \
                 Write your own executor if you need to upgrade executor on existing chain.",
            );
        }
    }
}

fn visit_custom_instructions(executor: &mut Executor, isi: &CustomInstruction) {
    if let Ok(isi) = multisig::MultisigInstructionBox::try_from(isi.payload()) {
        return isi.visit_execute(executor);
    };

    deny!(executor, "unexpected custom instruction");
}

trait VisitExecute: Instruction {
    fn visit_execute(self, executor: &mut Executor) {
        self.visit(executor);
        if executor.verdict().is_ok() {
            if let Err(err) = self.execute(executor) {
                executor.deny(err);
            }
        }
    }

    fn visit(&self, _executor: &mut Executor) {
        unimplemented!("should be overridden unless `Self::visit_execute` is overridden")
    }

    fn execute(self, _executor: &mut Executor) -> Result<(), ValidationFail> {
        unimplemented!("should be overridden unless `Self::visit_execute` is overridden")
    }
}

/// Migrate previous executor to the current version.
/// Called by Iroha once just before upgrading executor.
///
/// # Errors
///
/// Concrete errors are specific to the implementation.
///
/// If `migrate()` entrypoint fails then the whole `Upgrade` instruction
/// will be denied and previous executor will stay unchanged.
#[entrypoint]
fn migrate(host: Iroha, context: Context) {
    Executor::ensure_genesis(context.curr_block);
    DataModelBuilder::with_default_permissions()
        .add_instruction::<multisig::MultisigInstructionBox>()
        .add_instruction::<multisig::MultisigRegister>()
        .add_instruction::<multisig::MultisigPropose>()
        .add_instruction::<multisig::MultisigApprove>()
        .build_and_set(&host);
}
