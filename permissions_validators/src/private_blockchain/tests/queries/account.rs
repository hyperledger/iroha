use super::*;

#[test]
fn find_all_accounts() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let op = QueryBox::FindAllAccounts(FindAllAccounts::new());

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_deny());
        assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_deny());
    }
}

#[test]
fn find_account_by_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let op = QueryBox::FindAccountById(FindAccountById::new(alice_id.clone()));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_allow());
        assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_allow());
        assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_allow());
        assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_deny());
    }
}

#[test]
fn find_account_key_value_by_id_and_key() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let name: Name = "name".parse().expect("Valid");
    let op = QueryBox::FindAccountKeyValueByIdAndKey(FindAccountKeyValueByIdAndKey::new(
        alice_id.clone(),
        name,
    ));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_allow());
        assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_allow());
        assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_allow());
        assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_deny());
    }
}

#[test]
fn find_account_by_name() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let name: Name = "alice".parse().expect("Valid");
    let op = QueryBox::FindAccountsByName(FindAccountsByName::new(name));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_deny());
        assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_deny());
    }
}

#[test]
fn find_accounts_by_domain_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wonderland: (wonderland_id, _),
        denoland: (second_domain_id, _),
        wsv,
        ..
    } = TestEnv::new();

    let find_by_first_domain =
        QueryBox::FindAccountsByDomainId(FindAccountsByDomainId::new(wonderland_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_by_first_domain, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_by_first_domain, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_by_first_domain, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_by_first_domain, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_by_first_domain, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_by_first_domain, &wsv)
            .is_deny());
    }

    let find_by_second_domain =
        QueryBox::FindAccountsByDomainId(FindAccountsByDomainId::new(second_domain_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_by_second_domain, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_by_second_domain, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_by_second_domain, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_by_second_domain, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_by_second_domain, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_by_second_domain, &wsv)
            .is_deny());
    }
}

#[test]
fn find_accounts_with_asset() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let asset_definition_id: <AssetDefinition as Identifiable>::Id =
        "xor#wonderland".parse().expect("Valid");
    let op = QueryBox::FindAccountsWithAsset(FindAccountsWithAsset::new(asset_definition_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_deny());
        assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_deny());
        assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_deny());
    }
}
