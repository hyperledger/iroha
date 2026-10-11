//! Smoke test: Kotodama role ops compile to correct pointer-ABI syscalls
//! and execute against the mock WSV host.
use ivm::{
    AssetDefinitionId, IVM, PermissionToken,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
const TEST_ACCOUNT_LITERAL: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const TEST_ASSET_LITERAL: &str = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
fn make_vm_with_wsv() -> (IVM, AccountId) {
    let alice: AccountId =
        iroha_data_model::account::AccountId::parse_encoded(TEST_ACCOUNT_LITERAL)
            .expect("parse test account literal");
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(alice.clone());
    wsv.grant_permission(&alice, PermissionToken::ManageRoles);
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(1_000_000);
    vm.set_host(host);
    (vm, alice)
}
#[test]
fn kotodama_roles_roundtrip_on_wsvhost() {
    let (mut vm, alice) = make_vm_with_wsv();
    let compiler = KotodamaCompiler::new();
    // 1) Create role `minter` with permission mint_asset:rose#wonder
    let src_create = r#"
        seiyaku CreateRole { permission ManageRoles;
        kotoage fn main() authorize(ManageRoles) {
          ledger::role::register(role: Name::parse("minter"), permissions: Json::parse("{\"perms\":[\"mint_asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM\"]}"));
        }
        }
    "#;
    let prog = compiler
        .compile_source(src_create)
        .expect("compile create_role");
    vm.load_program(&prog).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run().expect("create_role should succeed");
    // Inspect host state
    {
        let host_any = vm.host_mut_any().unwrap();
        let host = host_any
            .downcast_mut::<WsvHost>()
            .expect("downcast WsvHost");
        assert!(
            !host
                .wsv
                .create_role("minter", std::collections::HashSet::new()),
            "role should exist"
        );
    }
    // 2) Grant role to alice and check derived permission
    let src_grant = r#"
        seiyaku GrantRole { permission ManageRoles;
        kotoage fn main() authorize(ManageRoles) {
          ledger::role::grant(account: context::authority(), role: Name::parse("minter"));
        }
        }
    "#;
    let prog = compiler
        .compile_source(src_grant)
        .expect("compile grant_role");
    vm.load_program(&prog).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run().expect("grant_role should succeed");
    {
        let host_any = vm.host_mut_any().unwrap();
        let host = host_any
            .downcast_mut::<WsvHost>()
            .expect("downcast WsvHost");
        let asset: AssetDefinitionId = TEST_ASSET_LITERAL.parse().unwrap();
        let tok = PermissionToken::MintAsset(asset);
        assert!(
            host.wsv.has_permission(&alice, &tok),
            "alice should inherit mint permission via role"
        );
    }
    // 3) Revoke role and delete; verify permissions removed and role absent
    let src_cleanup = r#"
        seiyaku RevokeAndDeleteRole { permission ManageRoles;
        kotoage fn main() authorize(ManageRoles) {
          ledger::role::revoke(account: context::authority(), role: Name::parse("minter"));
          ledger::role::unregister(role: Name::parse("minter"));
        }
        }
    "#;
    let prog = compiler
        .compile_source(src_cleanup)
        .expect("compile revoke/delete");
    vm.load_program(&prog).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run().expect("revoke+delete should succeed");
    {
        let host_any = vm.host_mut_any().unwrap();
        let host = host_any
            .downcast_mut::<WsvHost>()
            .expect("downcast WsvHost");
        let asset: AssetDefinitionId = TEST_ASSET_LITERAL.parse().unwrap();
        let tok = PermissionToken::MintAsset(asset);
        assert!(
            !host.wsv.has_permission(&alice, &tok),
            "permission should be removed after revoke"
        );
        // delete_role returns false if role still exists; we can probe by trying to delete again (should be false because already removed)
        assert!(!host.wsv.delete_role("minter"), "role should be deleted");
    }
}
