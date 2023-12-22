//! Runtime Executor which allows any instruction executed by `admin@admin` account.
//! If authority is not `admin@admin` then default validation is used as a backup.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_executor::{parse, prelude::*};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_instruction))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

fn visit_instruction(executor: &mut Executor, authority: &AccountId, isi: &InstructionBox) {
    if parse!("admin@admin" as AccountId) == *authority {
        execute!(executor, isi);
    }

    iroha_executor::default::visit_instruction(executor, authority, isi);
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    Ok(())
}
