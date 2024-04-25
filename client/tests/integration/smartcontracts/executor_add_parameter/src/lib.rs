//! Runtime Executor which adds new parameter `max_accounts_per_domain`.
//! And checks that parameter when registering new account.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use lol_alloc::{FreeListAllocator, LockedAllocator};

use iroha_executor::data_model::parameter::ParameterValueBox;
use iroha_executor::debug::{dbg_panic, DebugExpectExt};
use iroha_executor::prelude::*;

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_register_account))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

const MAX_ACCOUNTS_PER_DOMAIN: &str = "max_accounts_per_domain";

fn visit_register_account(executor: &mut Executor, _authority: &AccountId, isi: &Register<Account>) {
    if executor.block_height() == 0 {
        execute!(executor, isi);
    }

    let max_accounts_per_domain = get_max_accounts_per_domain();

    let domain_id = isi.object().id().domain_id();
    let number_accounts = FindAccountsByDomainId::new(domain_id.clone())
        .execute()
        .dbg_expect("Failed to execute FindAccountsByDomainId")
        .into_iter()
        .count();

    if number_accounts >= max_accounts_per_domain {
        deny!(executor, "Exceed max accounts per domain limit");
    }

    execute!(executor, isi);
}

fn get_max_accounts_per_domain() -> usize {
    let parameter_id: ParameterId = MAX_ACCOUNTS_PER_DOMAIN
        .parse()
        .dbg_expect("Valid parameter name");
    let parameters = FindAllParameters::new()
        .execute()
        .dbg_expect("Failed to execute FindAllParameters")
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .dbg_expect("Failed to execute FindAllParameters");
    let parameter = parameters
        .into_iter()
        .find(|parameter| parameter.id() == &parameter_id)
        .dbg_expect("Can't find parameter");
    let ParameterValueBox::Numeric(value) = parameter.val() else {
        dbg_panic("Unexpected parameter value");
    };
    let value: u64 = value
        .clone()
        .try_into()
        .dbg_expect("Can't cast parameter value to usize");
    value as usize
}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    let parameter_id: ParameterId = MAX_ACCOUNTS_PER_DOMAIN
        .parse()
        .dbg_expect("Valid parameter name");
    let parameter = Parameter::new(parameter_id, Numeric::new(1, 0).into());
    iroha_executor::add_parameter(&parameter)?;
    Ok(())
}
