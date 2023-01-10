use super::*;

#[test]
fn find_all_roles() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_all_roles = QueryBox::FindAllRoles(FindAllRoles::new());

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_all_roles, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_all_roles, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_all_roles, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_all_roles, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_all_roles, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_all_roles, &wsv)
            .is_deny());
    }
}

#[test]
fn find_all_role_ids() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_all_role_ids = QueryBox::FindAllRoleIds(FindAllRoleIds::new());

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_all_role_ids, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_all_role_ids, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_all_role_ids, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_all_role_ids, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_all_role_ids, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_all_role_ids, &wsv)
            .is_deny());
    }
}

#[test]
fn find_roles_by_account_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_by_alice = QueryBox::FindRolesByAccountId(FindRolesByAccountId::new(alice_id.clone()));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_by_alice, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_by_alice, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_by_alice, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_by_alice, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&bob_id, &find_by_alice, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_by_alice, &wsv)
            .is_deny());
    }
}

#[test]
fn find_role_by_role_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let role_id: <Role as Identifiable>::Id = "admin".parse().expect("Valid");
    let find_by_admin = QueryBox::FindRoleByRoleId(FindRoleByRoleId::new(role_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_by_admin, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_by_admin, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_by_admin, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_by_admin, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_by_admin, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_by_admin, &wsv)
            .is_deny());
    }
}
