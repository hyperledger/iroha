//! End-to-end tests for Kotodama domain builtins: unregister_domain and transfer_domain.
use iroha_model_base::domain::DomainId;
use ivm::{
    IVM,
    mock_wsv::{AccountId, MockWorldStateView, PermissionToken, WsvHost},
};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn kotodama_unregister_domain() {
    // Program unregisters a domain using a constructor
    let src = r#"
        seiyaku UnregisterDomain { permission FixtureAccess;
            kotoage fn main() authorize(FixtureAccess) {
                ledger::domain::unregister(domain: DomainId::parse("wonderland.universal"));
            }
        }
    "#;
    unsafe { std::env::set_var("IVM_COMPILER_DEBUG", "1") };
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile kotodama");
    // Prepare WSV with the domain present and caller permitted to register domains
    let mut wsv = MockWorldStateView::new();
    // Use a caller in a different domain to allow unregistering `wonderland.universal`
    // (no accounts in that domain).
    let _admin_domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("admin", "universal").expect("domain id");
    let alice: AccountId = AccountId::new(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key"),
    );
    let dom: DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").unwrap();
    wsv.add_account_unchecked(alice.clone());
    wsv.grant_permission(&alice, PermissionToken::RegisterDomain);
    assert!(wsv.register_domain(&alice, dom));
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("unregister_domain should validate TLV and queue ISI");
}
#[test]
fn kotodama_transfer_domain() {
    // Program transfers a domain from the execution authority to bob.
    let src = r#"
        seiyaku TransferDomain { permission FixtureAccess;
        kotoage fn main() authorize(FixtureAccess) {
          ledger::domain::transfer(source: context::authority(), domain: DomainId::parse("wonderland.universal"), destination: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"));
        }
        }
    "#;
    unsafe { std::env::set_var("IVM_COMPILER_DEBUG", "1") };
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile kotodama");
    let mut wsv = MockWorldStateView::new();
    let _wonderland_domain: DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain id");
    let alice: AccountId = AccountId::new(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key"),
    );
    wsv.add_account_unchecked(alice.clone());
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("transfer_domain should validate TLVs and queue ISI");
}
