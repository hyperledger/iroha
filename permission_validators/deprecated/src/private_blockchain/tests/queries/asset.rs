use super::*;

#[test]
fn find_all_assets() {
    let TestEnv { alice_id, wsv, .. } = TestEnv::new();

    let op = QueryBox::FindAllAssets(FindAllAssets::new());

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_deny());
    }
}

#[test]
fn find_all_assets_definitions() {
    let TestEnv { alice_id, wsv, .. } = TestEnv::new();

    let op = QueryBox::FindAllAssetsDefinitions(FindAllAssetsDefinitions::new());

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_deny());
    }
}

#[test]
fn find_asset_by_id() {
    let TestEnv {
        alice_id,
        carol_id,
        wsv,
        gold_asset_id,
        silver_asset_id,
        bronze_asset_id,
        ..
    } = TestEnv::new();

    let find_gold = QueryBox::FindAssetById(FindAssetById::new(gold_asset_id));
    let find_silver = QueryBox::FindAssetById(FindAssetById::new(silver_asset_id));
    let find_bronze = QueryBox::FindAssetById(FindAssetById::new(bronze_asset_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_silver, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_bronze, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_bronze, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&alice_id, &find_silver, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_bronze, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&alice_id, &find_bronze, &wsv)
            .is_deny());
    }
}

#[test]
fn find_asset_definition_by_id() {
    let TestEnv {
        alice_id,
        carol_id,
        wsv,
        gold_asset_definition_id,
        silver_asset_definition_id,
        bronze_asset_definition_id,
        ..
    } = TestEnv::new();

    let find_gold =
        QueryBox::FindAssetDefinitionById(FindAssetDefinitionById::new(gold_asset_definition_id));
    let find_silver =
        QueryBox::FindAssetDefinitionById(FindAssetDefinitionById::new(silver_asset_definition_id));
    let find_bronze =
        QueryBox::FindAssetDefinitionById(FindAssetDefinitionById::new(bronze_asset_definition_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_silver, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_bronze, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_bronze, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_silver, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_bronze, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_bronze, &wsv)
            .is_deny());
    }
}

#[test]
fn find_assets_by_name() {
    let TestEnv {
        alice_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_gold = QueryBox::FindAssetsByName(FindAssetsByName::new(
        Name::from_str("gold").expect("Valid"),
    ));
    let find_silver = QueryBox::FindAssetsByName(FindAssetsByName::new(
        Name::from_str("silver").expect("Valid"),
    ));
    let find_bronze = QueryBox::FindAssetsByName(FindAssetsByName::new(
        Name::from_str("bronze").expect("Valid"),
    ));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&alice_id, &find_silver, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_bronze, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&alice_id, &find_bronze, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_silver, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_bronze, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_bronze, &wsv)
            .is_deny());
    }
}

#[test]
fn find_assets_by_account_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let op = QueryBox::FindAssetsByAccountId(FindAssetsByAccountId::new(alice_id.clone()));

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
fn find_assets_by_asset_definition_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        gold_asset_definition_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_gold = QueryBox::FindAssetsByAssetDefinitionId(FindAssetsByAssetDefinitionId::new(
        gold_asset_definition_id,
    ));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_gold, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_gold, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_gold, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_gold, &wsv)
            .is_deny());
    }
}

#[test]
fn find_assets_by_domain_id() {
    let TestEnv {
        alice_id,
        wonderland: (wonderland_id, _),
        denoland: (denoland_id, _),
        wsv,
        ..
    } = TestEnv::new();

    let find_by_wonderland =
        QueryBox::FindAssetsByDomainId(FindAssetsByDomainId::new(wonderland_id));
    let find_by_denoland = QueryBox::FindAssetsByDomainId(FindAssetsByDomainId::new(denoland_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_by_wonderland, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_by_denoland, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_by_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_by_denoland, &wsv)
            .is_deny())
    }
}

#[test]
fn find_assets_by_domain_id_and_asset_definition_id() {
    let TestEnv {
        alice_id,
        gold_asset_definition_id,
        bronze_asset_definition_id,
        wonderland: (wonderland_id, _),
        denoland: (denoland_id, _),
        wsv,
        ..
    } = TestEnv::new();

    let find_gold_by_wonderland = QueryBox::FindAssetsByDomainIdAndAssetDefinitionId(
        FindAssetsByDomainIdAndAssetDefinitionId::new(
            wonderland_id.clone(),
            gold_asset_definition_id.clone(),
        ),
    );
    let find_gold_by_denoland = QueryBox::FindAssetsByDomainIdAndAssetDefinitionId(
        FindAssetsByDomainIdAndAssetDefinitionId::new(
            denoland_id.clone(),
            gold_asset_definition_id,
        ),
    );

    let find_bronze_by_wonderland = QueryBox::FindAssetsByDomainIdAndAssetDefinitionId(
        FindAssetsByDomainIdAndAssetDefinitionId::new(
            wonderland_id,
            bronze_asset_definition_id.clone(),
        ),
    );
    let find_bronze_by_denoland = QueryBox::FindAssetsByDomainIdAndAssetDefinitionId(
        FindAssetsByDomainIdAndAssetDefinitionId::new(denoland_id, bronze_asset_definition_id),
    );

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold_by_wonderland, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_gold_by_denoland, &wsv)
            .is_deny());

        assert!(only_accounts_domain
            .check(&alice_id, &find_bronze_by_wonderland, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_bronze_by_denoland, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold_by_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_gold_by_denoland, &wsv)
            .is_deny());

        assert!(only_accounts_data
            .check(&alice_id, &find_bronze_by_wonderland, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&alice_id, &find_bronze_by_denoland, &wsv)
            .is_deny());
    }
}

#[test]
fn find_asset_quantity_by_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        gold_asset_id,
        silver_asset_id,
        bronze_asset_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_gold_quantity =
        QueryBox::FindAssetQuantityById(FindAssetQuantityById::new(gold_asset_id));
    let find_silver_quantity =
        QueryBox::FindAssetQuantityById(FindAssetQuantityById::new(silver_asset_id));
    let find_bronze_quantity =
        QueryBox::FindAssetQuantityById(FindAssetQuantityById::new(bronze_asset_id));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold_quantity, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_gold_quantity, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_bronze_quantity, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_gold_quantity, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_bronze_quantity, &wsv)
            .is_allow());
    }
    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold_quantity, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&bob_id, &find_silver_quantity, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&carol_id, &find_bronze_quantity, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&alice_id, &find_silver_quantity, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_bronze_quantity, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_gold_quantity, &wsv)
            .is_deny());
    }
}

#[test]
fn find_asset_key_value_by_id_and_key() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        gold_asset_id,
        silver_asset_id,
        bronze_asset_id,
        wsv,
        ..
    } = TestEnv::new();
    let name: Name = "foo".parse().expect("Valid");
    let find_gold_key_value = QueryBox::FindAssetKeyValueByIdAndKey(
        FindAssetKeyValueByIdAndKey::new(gold_asset_id, name.clone()),
    );
    let find_silver_key_value = QueryBox::FindAssetKeyValueByIdAndKey(
        FindAssetKeyValueByIdAndKey::new(silver_asset_id, name.clone()),
    );
    let find_bronze_key_value = QueryBox::FindAssetKeyValueByIdAndKey(
        FindAssetKeyValueByIdAndKey::new(bronze_asset_id, name),
    );

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_gold_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_bronze_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_gold_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_bronze_key_value, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&bob_id, &find_silver_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&carol_id, &find_bronze_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&alice_id, &find_silver_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_gold_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_bronze_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_gold_key_value, &wsv)
            .is_deny());
    }
}

#[test]
fn find_asset_definition_key_value_by_id_and_key() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        gold_asset_definition_id,
        silver_asset_definition_id,
        bronze_asset_definition_id,
        wsv,
        ..
    } = TestEnv::new();
    let name: Name = "foo".parse().expect("Valid");
    let find_gold_key_value = QueryBox::FindAssetDefinitionKeyValueByIdAndKey(
        FindAssetDefinitionKeyValueByIdAndKey::new(gold_asset_definition_id, name.clone()),
    );
    let find_silver_key_value = QueryBox::FindAssetDefinitionKeyValueByIdAndKey(
        FindAssetDefinitionKeyValueByIdAndKey::new(silver_asset_definition_id, name.clone()),
    );
    let find_bronze_key_value = QueryBox::FindAssetDefinitionKeyValueByIdAndKey(
        FindAssetDefinitionKeyValueByIdAndKey::new(bronze_asset_definition_id, name),
    );
    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_gold_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_gold_key_value, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_bronze_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_gold_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_bronze_key_value, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_gold_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_silver_key_value, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_bronze_key_value, &wsv)
            .is_deny());
    }
}
