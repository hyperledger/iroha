//! End-to-end canonical entity registration calls through the pointer ABI.
use ivm::{IVM, MockWorldStateView, PermissionToken, mock_wsv::WsvHost};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn kotodama_register_account_and_unregister_asset() {
    // Program: register domain, then register an account, then register asset and unregister it
    let src = r#"
        seiyaku RegisterAndUnregisterEntities { permission ManageEntities;
        kotoage fn main() authorize(ManageEntities) {
          ledger::domain::register(domain: DomainId::parse("default.universal"));
          ledger::account::register(account: AccountId::parse("sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76"));
          ledger::asset::register(asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
          ledger::asset::unregister(asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"));
          ledger::account::unregister(account: AccountId::parse("sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76"));
        }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile");
    // Prepare WSV host with permissions for the caller
    let _domain: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain id");
    let caller: ivm::mock_wsv::AccountId = ivm::mock_wsv::AccountId::new(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key"),
    );
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(&caller, PermissionToken::RegisterDomain);
    wsv.grant_permission(&caller, PermissionToken::RegisterAccount);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("program should run with WsvHost TLV validation");
}
