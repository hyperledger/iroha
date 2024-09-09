//! Runtime Executor which extends instruction set with one custom instruction - [MintAssetForAllAccounts].
//! This instruction is handled in executor, and translates to multiple usual ISIs.
//! It is possible to use queries during execution.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::simple_isi::{CustomInstructionBox, MintAssetForAllAccounts};
use iroha_executor::{data_model::isi::CustomInstruction, debug::DebugExpectExt, prelude::*};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Visit, Execute, Entrypoints)]
#[visit(custom(visit_custom))]
struct Executor {
    host: Iroha,
    context: Context,
    verdict: Result,
}

fn visit_custom(executor: &mut Executor, isi: &CustomInstruction) {
    let Ok(isi) = CustomInstructionBox::try_from(isi.payload()) else {
        deny!(executor, "Failed to parse custom instruction");
    };
    match execute_custom_instruction(isi, executor.host()) {
        Ok(()) => return,
        Err(err) => {
            deny!(executor, err);
        }
    }
}

fn execute_custom_instruction(
    isi: CustomInstructionBox,
    host: &Iroha,
) -> Result<(), ValidationFail> {
    match isi {
        CustomInstructionBox::MintAssetForAllAccounts(isi) => {
            execute_mint_asset_for_all_accounts(isi, host)
        }
    }
}

fn execute_mint_asset_for_all_accounts(
    isi: MintAssetForAllAccounts,
    host: &Iroha,
) -> Result<(), ValidationFail> {
    let accounts = host
        .query(FindAccountsWithAsset::new(isi.asset_definition.clone()))
        .execute()?;

    for account in accounts {
        let account = account.dbg_expect("Failed to get accounts with asset");
        let asset_id = AssetId::new(isi.asset_definition.clone(), account.id().clone());
        host.submit(&Mint::asset_numeric(isi.quantity, asset_id))?;
    }
    Ok(())
}

#[entrypoint]
fn migrate(host: Iroha, _context: Context) {
    DataModelBuilder::with_default_permissions()
        .add_instruction::<CustomInstructionBox>()
        .add_instruction::<MintAssetForAllAccounts>()
        .build_and_set(&host);
}
