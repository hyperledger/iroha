//! Runtime Executor which allows any instruction executed by [admin](crate::integration::upgrade::ADMIN_ID) account.
//! If authority is not admin then default validation is used as a backup.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use iroha_executor::prelude::*;

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_instruction))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

fn visit_instruction(executor: &mut Executor, authority: &AccountId, isi: &InstructionBox) {
    // multihash equals to integration::upgrade::ADMIN_PUBLIC_KEY_MULTIHASH
    let admin_id = "ed012076E5CA9698296AF9BE2CA45F525CB3BCFDEB7EE068BA56F973E9DD90564EF4FC@admin"
        .parse()
        .unwrap();
    if *authority == admin_id {
        execute!(executor, isi);
    }

    iroha_executor::default::visit_instruction(executor, authority, isi);
}

#[entrypoint]
fn migrate(_block_height: u64) {}
