//! Runtime Executor which allows domains whose id satisfies the length limit
#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::format;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::parameters::DomainLimits;
use iroha_executor::{prelude::*, smart_contract::query_single, DataModelBuilder};
use iroha_executor_data_model::parameter::Parameter;

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_register_domain))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

fn visit_register_domain(executor: &mut Executor, _authority: &AccountId, isi: &Register<Domain>) {
    let parameters = query_single(FindParameters).dbg_unwrap();

    let domain_limits: DomainLimits = parameters
        .custom()
        .get(&DomainLimits::id())
        .unwrap()
        .try_into()
        .expect("INTERNAL BUG: Failed to deserialize json as `DomainLimits`");

    iroha_executor::log::info!(&format!("Registering domain: {}", isi.object().id()));
    if isi.object().id().name().as_ref().len() > domain_limits.id_len as usize {
        deny!(executor, "Domain id exceeds the limit");
    }

    execute!(executor, isi);
}

#[entrypoint]
fn migrate(_block_height: u64) {
    DataModelBuilder::with_default_permissions()
        .add_parameter(DomainLimits::default())
        .build_and_set();
}
