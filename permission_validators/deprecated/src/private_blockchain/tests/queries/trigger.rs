use super::*;

#[test]
fn find_all_active_trigger_ids() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_all_active_triggers = QueryBox::FindAllActiveTriggerIds(FindAllActiveTriggerIds {});

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        // Always allow for any account.
        assert!(only_accounts_domain
            .check(&alice_id, &find_all_active_triggers, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_all_active_triggers, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_all_active_triggers, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        // Always returns an error for any account.
        assert!(only_accounts_data
            .check(&alice_id, &find_all_active_triggers, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_all_active_triggers, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_all_active_triggers, &wsv)
            .is_deny());
    }
}

#[test]
fn find_trigger_by_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        mintbox_gold_trigger_id,
        ..
    } = TestEnv::new();

    let find_trigger = QueryBox::FindTriggerById(FindTriggerById {
        id: mintbox_gold_trigger_id.into(),
    });

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_trigger, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_trigger, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_trigger, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_trigger, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&bob_id, &find_trigger, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_trigger, &wsv)
            .is_deny());
    }
}

#[test]
fn find_trigger_key_value_by_id_and_key() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        mintbox_gold_trigger_id,
        ..
    } = TestEnv::new();

    let name: Name = "foo".parse().expect("Valid");
    let find_trigger = QueryBox::FindTriggerKeyValueByIdAndKey(FindTriggerKeyValueByIdAndKey {
        id: mintbox_gold_trigger_id.into(),
        key: name.into(),
    });

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_trigger, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_trigger, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_trigger, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_trigger, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&bob_id, &find_trigger, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_trigger, &wsv)
            .is_deny());
    }
}

#[test]
fn find_triggers_by_domain_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wonderland: (wonderland_id, _),
        denoland: (denoland_id, _),
        wsv,
        ..
    } = TestEnv::new();

    let find_trigger_by_wonderland =
        QueryBox::FindTriggersByDomainId(FindTriggersByDomainId::new(wonderland_id));
    let find_trigger_by_denoland =
        QueryBox::FindTriggersByDomainId(FindTriggersByDomainId::new(denoland_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_trigger_by_wonderland, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_trigger_by_denoland, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_trigger_by_wonderland, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_trigger_by_denoland, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_trigger_by_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_trigger_by_denoland, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_trigger_by_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_trigger_by_denoland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_trigger_by_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_trigger_by_denoland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_trigger_by_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_trigger_by_denoland, &wsv)
            .is_deny());
    }
}
