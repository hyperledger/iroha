//! Runtime Executor which removes [`token::CanControlDomainLives`] permission token.
//! Needed for tests.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::{format, string::String};

use iroha_executor::{parameter::Parameter, prelude::*, DataModelBuilder};
use iroha_schema::IntoSchema;
use lol_alloc::{FreeListAllocator, LockedAllocator};
use serde::{Deserialize, Serialize};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_register_domain, visit_set_parameter))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

fn visit_set_parameter(executor: &mut Executor, _authority: &AccountId, isi: &SetParameter) {
    execute!(executor, isi);
}

fn visit_register_domain(executor: &mut Executor, _authority: &AccountId, isi: &Register<Domain>) {
    // FIXME: unwrap is ok here?
    let required_prefix = FindAllParameters
        .execute()
        .unwrap()
        .iter()
        .map(Result::unwrap)
        .find_map(|parameter| EnforceDomainPrefix::try_from_object(&parameter).ok());

    if let Some(EnforceDomainPrefix { prefix }) = required_prefix {
        let domain_id = isi.object().id().name().as_ref();
        if domain_id.strip_prefix(&prefix).is_none() {
            deny!(
                executor,
                "Domain `{domain_id}` must be prefixed with `{prefix}`"
            );
        }
    }

    execute!(executor, isi);
}

#[derive(IntoSchema, Serialize, Deserialize)]
struct EnforceDomainPrefix {
    prefix: String,
}

impl iroha_executor::parameter::Parameter for EnforceDomainPrefix {}

#[entrypoint]
pub fn migrate(_block_height: u64) -> MigrationResult {
    // Note that actually migration will reset token schema to default (minus `CanUnregisterDomain`)
    // So any added custom permission tokens will be also removed
    let mut data_model = DataModelBuilder::new();
    data_model.add_parameter::<EnforceDomainPrefix>();
    iroha_executor::set_data_model(&data_model.serialize());

    Ok(())
}
