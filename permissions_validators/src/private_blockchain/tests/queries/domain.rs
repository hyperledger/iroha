use super::*;

#[test]
fn find_all_domains() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_all_domains = QueryBox::FindAllDomains(FindAllDomains::new());

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_all_domains, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_all_domains, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_all_domains, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_all_domains, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_all_domains, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_all_domains, &wsv)
            .is_deny());
    }
}

#[test]
fn find_domain_by_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wonderland: (wonderland_id, _),
        wsv,
        ..
    } = TestEnv::new();

    let find_wonderland = QueryBox::FindDomainById(FindDomainById::new(wonderland_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_wonderland, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_wonderland, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_wonderland, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_wonderland, &wsv)
            .is_deny());
    }
}

#[test]
fn find_domain_key_value_by_id_and_key() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wonderland: (wonderland_id, _),
        wsv,
        ..
    } = TestEnv::new();

    let name: Name = "foo".parse().expect("Valid");
    let find_wonderland_key_value = QueryBox::FindDomainKeyValueByIdAndKey(
        FindDomainKeyValueByIdAndKey::new(wonderland_id, name),
    );

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_wonderland_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_wonderland_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_wonderland_key_value, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_wonderland_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_wonderland_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_wonderland_key_value, &wsv)
            .is_deny());
    }
}
