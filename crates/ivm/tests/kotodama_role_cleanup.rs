//! Adversarial lifecycle tests for canonical role operations.
use ivm::{
    IVM,
    mock_wsv::{MockWorldStateView, PermissionToken, WsvHost},
};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
fn load(vm: &mut IVM, program: &[u8], context: &str) {
    vm.load_program(program)
        .unwrap_or_else(|error| panic!("load {context}: {error:?}"));
    common::select_kotodama_entrypoint(vm, program, "main");
}
fn compile(body: &str) -> Vec<u8> {
    let src = format!(
        "seiyaku RoleOperation {{ permission ManageRoles;  kotoage fn main() authorize(ManageRoles) {{\n{body}\n}} }}"
    );
    let c = KotodamaCompiler::new();
    c.compile_source(&src).expect("compile")
}
fn caller_account() -> ivm::mock_wsv::AccountId {
    let _domain: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain id");
    ivm::mock_wsv::AccountId::new(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("public key"),
    )
}
fn literal_account() -> ivm::mock_wsv::AccountId {
    iroha_data_model::account::AccountId::parse_encoded(
        "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
    )
    .expect("parse test account literal")
}
#[test]
fn kotodama_revoke_role_denies_mint() {
    let caller: ivm::mock_wsv::AccountId = literal_account();
    // VM + host with bootstrap permissions
    let mut wsv = MockWorldStateView::new();
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::ManageRoles);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    // 1) Bootstrap + create+grant role + initial mint (should succeed)
    let prog_ok = compile(
        r#"
          ledger::asset::register(asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
          ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{\"perms\":[\"mint_asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"]}"));
          ledger::role::grant(account: context::authority(), role: Name::parse("minter"));
          ledger::asset::mint(account: context::authority(), asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), amount: 1);
    "#,
    );
    load(&mut vm, &prog_ok, "bootstrap role program");
    vm.run().expect("initial mint should succeed");
    // 2) Revoke role then attempt mint (should fail with PermissionDenied)
    let prog_revoke_then_mint = compile(
        r#"
          ledger::role::revoke(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), role: Name::parse("minter"));
          ledger::asset::mint(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), amount: 1);
    "#,
    );
    load(&mut vm, &prog_revoke_then_mint, "revoke role program");
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::PermissionDenied));
}
#[test]
fn kotodama_delete_role_prevents_grant() {
    let caller: ivm::mock_wsv::AccountId = caller_account();
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(&caller, PermissionToken::RegisterDomain);
    wsv.grant_permission(&caller, PermissionToken::RegisterAccount);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::ManageRoles);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    // Bootstrap + create role (no grant)
    let prog_boot = compile(
        r#"
          ledger::domain::register(domain: DomainId::parse("default.universal"));
          ledger::asset::register(asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
          ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{\"perms\":[\"mint_asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"]}"));
    "#,
    );
    load(&mut vm, &prog_boot, "bootstrap role program");
    vm.run().expect("boot ok");
    // Delete role then try to grant it (should fail)
    let prog_delete_then_grant = compile(
        r#"
          ledger::role::unregister(role: Name::parse("minter"));
          ledger::role::grant(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), role: Name::parse("minter"));
    "#,
    );
    load(
        &mut vm,
        &prog_delete_then_grant,
        "delete then grant role program",
    );
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::PermissionDenied));
}
#[test]
fn kotodama_delete_role_denied_while_assigned_then_succeeds_after_revoke() {
    let caller: ivm::mock_wsv::AccountId = caller_account();
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(&caller, PermissionToken::RegisterDomain);
    wsv.grant_permission(&caller, PermissionToken::RegisterAccount);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::ManageRoles);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    // Bootstrap: create role and grant it
    let boot = compile(
        r#"
          ledger::domain::register(domain: DomainId::parse("default.universal"));
          ledger::asset::register(asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
          ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{\"perms\":[\"mint_asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"]}"));
          ledger::role::grant(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), role: Name::parse("minter"));
    "#,
    );
    load(&mut vm, &boot, "bootstrap role program");
    vm.run().expect("boot ok");
    // Attempt to delete role while still assigned -> should be denied
    let del = compile(
        r#" ledger::role::unregister(role: Name::parse("minter"));
    "#,
    );
    load(&mut vm, &del, "delete assigned role program");
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::PermissionDenied));
    // Revoke then delete -> should succeed
    let revoke_delete = compile(
        r#"
          ledger::role::revoke(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), role: Name::parse("minter"));
          ledger::role::unregister(role: Name::parse("minter"));
    "#,
    );
    load(&mut vm, &revoke_delete, "revoke and delete role program");
    vm.run().expect("revoke then delete ok");
}
#[test]
fn kotodama_combined_revoke_then_delete_blocks_grant_and_mint() {
    let caller: ivm::mock_wsv::AccountId = caller_account();
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(&caller, PermissionToken::RegisterDomain);
    wsv.grant_permission(&caller, PermissionToken::RegisterAccount);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::ManageRoles);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    // Bootstrap + create and grant role
    let boot = compile(
        r#"
          ledger::domain::register(domain: DomainId::parse("default.universal"));
          ledger::asset::register(asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
          ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{\"perms\":[\"mint_asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"]}"));
          ledger::role::grant(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), role: Name::parse("minter"));
    "#,
    );
    load(&mut vm, &boot, "bootstrap role program");
    vm.run().expect("boot ok");
    // Revoke then delete role
    let revoke_delete = compile(
        r#"
          ledger::role::revoke(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), role: Name::parse("minter"));
          ledger::role::unregister(role: Name::parse("minter"));
    "#,
    );
    load(&mut vm, &revoke_delete, "revoke and delete role program");
    vm.run().expect("revoke+delete ok");
    // Attempt to grant role now fails (role no longer exists)
    let grant_again = compile(
        r#"
          ledger::role::grant(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), role: Name::parse("minter"));
    "#,
    );
    load(&mut vm, &grant_again, "grant deleted role program");
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::PermissionDenied));
    // Mint is denied without the role
    let mint = compile(
        r#"
          ledger::asset::mint(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), amount: 1);
    "#,
    );
    load(&mut vm, &mint, "mint after role deletion program");
    let err2 = vm.run().unwrap_err();
    assert!(matches!(err2, ivm::VMError::PermissionDenied));
}
