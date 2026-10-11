//! End-to-end tests for canonical role and permission builtins.
use ivm::{
    IVM,
    mock_wsv::{MockWorldStateView, PermissionToken, WsvHost},
};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
const TEST_ACCOUNT_LITERAL: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const TEST_CALLER_PUBLIC_KEY: &str =
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
fn literal_account() -> ivm::mock_wsv::AccountId {
    iroha_data_model::account::AccountId::parse_encoded(TEST_ACCOUNT_LITERAL)
        .expect("parse test account literal")
}
fn public_key_account() -> ivm::mock_wsv::AccountId {
    ivm::mock_wsv::AccountId::new(
        TEST_CALLER_PUBLIC_KEY
            .parse()
            .expect("test public key must parse"),
    )
}
#[test]
fn kotodama_create_and_grant_role_enables_mint() {
    let src = r#"
        seiyaku RoleBootstrap { permission ManageRoles;
        kotoage fn main() authorize(ManageRoles) {
          // Bootstrap the asset definition used by the role permission.
          ledger::asset::register(asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), name: "ROSE", spec: NumericSpec::integer(), mintable: Mintable::Once);
          // Create role with mint permission and grant it to the caller.
          ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{\"perms\":[\"mint_asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"]}"));
          ledger::role::grant(account: context::authority(), role: Name::parse("minter"));
          // Mint using role permission
          ledger::asset::mint(account: context::authority(), asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), amount: 1);
        }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile");
    let caller = literal_account();
    let mut wsv = MockWorldStateView::new();
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::ManageRoles);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("program should execute with role-created permissions");
}
#[test]
fn kotodama_grant_role_accepts_runtime_account_argument() {
    let src = r#"
        seiyaku RuntimeRoleGrant { permission ManageRoles;
        fn grant_it(AccountId who) {
          ledger::role::grant(account: who, role: Name::parse("minter"));
        }

        kotoage fn main() authorize(ManageRoles) {
          ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{\"perms\":[\"mint_asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"]}"));
          let who = AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV");
          grant_it(who: who);
        }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile");
    let caller = public_key_account();
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(&caller, PermissionToken::RegisterDomain);
    wsv.grant_permission(&caller, PermissionToken::RegisterAccount);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::ManageRoles);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("grant_role should accept runtime account arguments");
}
#[test]
fn kotodama_grant_permission_accepts_runtime_account_argument() {
    let src = r#"
        seiyaku RuntimePermissionGrant { permission ManagePermissions;
        fn grant_it(AccountId who) {
          ledger::permission::grant(account: who, permission: Name::parse("BenefitSpend"));
        }

        kotoage fn main() authorize(ManagePermissions) {
          let who = AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV");
          grant_it(who: who);
        }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile");
    let caller = public_key_account();
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(&caller, PermissionToken::ManagePermissions);
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("grant_permission should accept runtime account arguments");
}
#[test]
fn kotodama_runtime_account_argument_survives_syscall_before_grant_permission() {
    let src = r#"
        seiyaku RuntimePermissionGrantAfterSyscall { permission ManagePermissions;
        fn grant_it(AccountId who) {
          let _now = context::transaction_time_ms();
          ledger::permission::grant(account: who, permission: Name::parse("BenefitSpend"));
        }

        kotoage fn main() authorize(ManagePermissions) {
          let who = AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV");
          grant_it(who: who);
        }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile");
    let caller = public_key_account();
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(&caller, PermissionToken::ManagePermissions);
    let mut host = WsvHost::new_with_subject(wsv, caller.clone());
    host.set_current_time_ms(1_717_171_717_000);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("runtime account arguments must survive intervening syscalls");
}
#[test]
fn kotodama_authority_matches_domainless_account_literal() {
    let src = r#"
        seiyaku AuthorityIdentity {
        view fn main() authorize(anyone) -> bool {
          let who = AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV");
          return context::authority() == who;
        }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile");
    let caller = literal_account();
    let wsv = MockWorldStateView::new();
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("context::authority() should match the domainless account literal");
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
