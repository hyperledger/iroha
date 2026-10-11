//! Kotodama structs: basic named-field access lowers to pointer-ABI and
//! passes CoreHost TLV validation for domain transfer.
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn struct_fields_lower_to_corehost_syscall_args() {
    // Define a struct with pointer-ABI fields and use it to call a builtin.
    // Field access uses named fields and should lower to numeric field indices
    // and ultimately to correct TLVs in r10/r11 for the syscall.
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
    let compiler = KotodamaCompiler::new();
    let prog = compiler
        .compile_source(src)
        .expect("compile Kotodama with struct fields");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&prog).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("CoreHost should validate &DomainId in r10 and &AccountId in r11");
}
