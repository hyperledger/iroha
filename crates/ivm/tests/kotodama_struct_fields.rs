//! Kotodama structs: field access lowering via pointer-ABI to CoreHost.
use ivm::{
    IVM,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn struct_fields_lower_to_syscall_args() {
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!(
            "Skipping: Kotodama struct field lowering test gated. Set IROHA_RUN_IGNORED=1 to run."
        );
        return;
    }
    // Define a struct with pointer-ABI fields and use it to call a builtin.
    let src = r#"
        seiyaku C { permission TransferDomain;
            struct TransferArgs { DomainId domain; AccountId to; }
            kotoage fn main() authorize(TransferDomain) {
                let args = TransferArgs {
                    domain: DomainId::parse("wonderland.universal"),
                    to: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"),
                };
                ledger::domain::transfer(source: context::authority(), domain: args.domain, destination: args.to);
            }
        }
    "#;
    // Note: set IVM_COMPILER_DEBUG=1 in the environment to debug codegen.
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile kotodama");
    let mut wsv = MockWorldStateView::new();
    // Ensure the target account exists in mock WSV to pass validation in host
    let _domain: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain id");
    let bob: AccountId = AccountId::new(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key"),
    );
    wsv.add_account_unchecked(bob.clone());
    let host = WsvHost::new_with_subject(wsv, bob.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run().expect("transfer_domain via struct fields");
}
