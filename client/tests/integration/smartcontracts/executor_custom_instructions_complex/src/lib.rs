//! Runtime Executor which extends instruction set with simple expression system.
//! Example of custom expression:
//! "If specific user has more then X amount of specific asset, burn Y amount of that asset"
//! This is expressed as [ConditionalExpr] with [Expression::Greater] and [Expression::Query] as condition.
//! Note that only few expressions are implemented to demonstrate proof-of-concept.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use executor_custom_data_model::complex_isi::{
    ConditionalExpr, CoreExpr, CustomInstructionExpr, Evaluate, Value,
};
use iroha_executor::{
    data_model::{isi::CustomInstruction, query::QueryOutputBox},
    prelude::*,
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Constructor, ValidateEntrypoints, Validate, Visit)]
#[visit(custom(visit_custom))]
struct Executor {
    verdict: Result,
    block_height: u64,
}

fn visit_custom(executor: &mut Executor, _authority: &AccountId, isi: &CustomInstruction) {
    let Ok(isi) = CustomInstructionExpr::try_from(isi.payload()) else {
        deny!(executor, "Failed to parse custom instruction");
    };
    match execute_custom_instruction(isi) {
        Ok(()) => return,
        Err(err) => {
            deny!(executor, err);
        }
    }
}

fn execute_custom_instruction(isi: CustomInstructionExpr) -> Result<(), ValidationFail> {
    match isi {
        CustomInstructionExpr::Core(isi) => execute_core(isi),
        CustomInstructionExpr::If(isi) => execute_if(*isi),
    }
}

fn execute_core(isi: CoreExpr) -> Result<(), ValidationFail> {
    let isi = isi.object.evaluate(&Context)?;
    isi.execute()
}

fn execute_if(isi: ConditionalExpr) -> Result<(), ValidationFail> {
    let condition = isi.condition.evaluate(&Context)?;
    if condition {
        execute_custom_instruction(isi.then)
    } else {
        Ok(())
    }
}

struct Context;

impl executor_custom_data_model::complex_isi::Context for Context {
    fn query(&self, query: &QueryBox) -> Result<Value, ValidationFail> {
        // Note: supported only queries which return numeric result
        match query.execute()?.into_inner() {
            QueryOutputBox::Numeric(value) => Ok(Value::Numeric(value)),
            _ => unimplemented!(),
        }
    }
}

#[entrypoint]
fn migrate(_block_height: u64) {
    DataModelBuilder::with_default_permissions()
        .add_instruction::<CustomInstructionExpr>()
        .add_instruction::<CoreExpr>()
        .add_instruction::<ConditionalExpr>()
        .build_and_set();
}
