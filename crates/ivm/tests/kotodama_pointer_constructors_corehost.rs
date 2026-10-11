//! End-to-end test: Kotodama pointer constructors lower to Norito TLVs and
//! CoreHost validates TLVs for SetAccountDetail.
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn kotodama_set_account_detail_with_constructors() {
    // Kotodama program uses typed pointer constructors for the host call.
    let src = r#"
        seiyaku SetAccountDetail { permission FixtureAccess;
        kotoage fn main() authorize(FixtureAccess) {
          // Use a valid AccountId multihash form for Iroha v2
          ledger::account::set_metadata(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), key: Name::parse("cursor"), value: Json::parse("{\"x\":1}"));
        }
        }
    "#;
    // Use default compiler options (no forced VECTOR bit)
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile kotodama");
    // Allow ample cycles so the program can mirror TLVs and perform the syscall.
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&prog).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("CoreHost should validate typed TLVs for name/json");
}
