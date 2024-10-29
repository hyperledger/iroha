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
    ConditionalExpr, CoreExpr, CustomInstructionExpr, Evaluate, NumericQuery, Value,
};
use iroha_executor::{
    data_model::{isi::CustomInstruction, query::builder::SingleQueryError},
    prelude::*,
};

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

getrandom::register_custom_getrandom!(iroha_executor::stub_getrandom);

#[derive(Visit, Execute, Entrypoints)]
#[visit(custom(visit_custom))]
struct Executor {
    host: Iroha,
    context: iroha_executor::prelude::Context,
    verdict: Result,
}

fn visit_custom(executor: &mut Executor, isi: &CustomInstruction) {
    let Ok(isi) = CustomInstructionExpr::try_from(isi.payload()) else {
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
    isi: CustomInstructionExpr,
    host: &Iroha,
) -> Result<(), ValidationFail> {
    match isi {
        CustomInstructionExpr::Core(isi) => execute_core(isi, host),
        CustomInstructionExpr::If(isi) => execute_if(*isi, host),
    }
}

fn execute_core(isi: CoreExpr, host: &Iroha) -> Result<(), ValidationFail> {
    let isi = &isi.object.evaluate(&Context { host })?;
    host.submit(isi)
}

fn execute_if(isi: ConditionalExpr, host: &Iroha) -> Result<(), ValidationFail> {
    let condition = isi.condition.evaluate(&Context { host })?;
    if condition {
        execute_custom_instruction(isi.then, host)
    } else {
        Ok(())
    }
}

struct Context<'i> {
    host: &'i Iroha,
}

impl executor_custom_data_model::complex_isi::Context for Context<'_> {
    fn query(&self, q: &NumericQuery) -> Result<Value, ValidationFail> {
        let result = match q.clone() {
            NumericQuery::FindAssetQuantityById(q) => self.host.query_single(q),
            NumericQuery::FindTotalAssetQuantityByAssetDefinitionId(asset_definition_id) => {
                let asset_definition = self
                    .host
                    .query(FindAssetsDefinitions::new())
                    .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id))
                    .execute_single()
                    .map_err(|e| match e {
                        SingleQueryError::QueryError(e) => e,
                        _ => unreachable!(),
                    })?;

                Ok(*asset_definition.total_quantity())
            }
        };

        result.map(Value::Numeric)
    }
}

#[entrypoint]
fn migrate(host: Iroha, _context: iroha_executor::prelude::Context) {
    DataModelBuilder::with_default_permissions()
        .add_instruction::<CustomInstructionExpr>()
        .add_instruction::<CoreExpr>()
        .add_instruction::<ConditionalExpr>()
        .build_and_set(&host);
}
