//! Owner, quote-bound, canonical dataspace and stale-policy namespace tests.
use super::*;
use iroha_data_model::sns::fixtures::{default_policy, steward_account};
use iroha_model_base::metadata::Metadata;

fn policy() -> SuffixPolicyV1 {
    let mut value = default_policy();
    value.suffix_id = DOMAIN_NAME_SUFFIX_ID;
    value.suffix = "domain".into();
    value.pricing[0].label_regex = "^[a-z]+\\.universal$".into();
    value
}

#[test]
fn exact_one_year_quote_binds_owner_policy_asset_rent_and_network_deadline() {
    let policy = policy();
    let owner = steward_account();
    let quote = quote_domain(
        &policy,
        DomainId::parse_fully_qualified("developer.universal").unwrap(),
        DataSpaceId::UNIVERSAL,
        owner.clone(),
        10_000,
        Duration::from_secs(600),
    )
    .unwrap();
    assert_eq!(quote.domain, "developer.universal");
    assert_eq!(quote.rent, "0.5".parse().unwrap());
    assert_eq!(quote.valid_until_ms, 310_000);
    let instruction = &quote.request.intents[0];
    assert_eq!(instruction.quote_guard.max_amount, quote.rent);
    assert_eq!(
        instruction.quote_guard.expected_policy_version,
        policy.policy_version
    );
    assert_eq!(
        instruction.quote_guard.expected_payment_asset,
        quote.payment_asset
    );
    assert_eq!(instruction.quote_guard.valid_until_ms, quote.valid_until_ms);
    assert_eq!(instruction.acquisition.term_years, 1);
    assert!(
        matches!(&instruction.intent, AliasIntentV1::Domain(value) if value.owner == owner && value.domain.dataspace_id == DataSpaceId::UNIVERSAL)
    );
    let wire = norito::json::to_vec(&quote.request).unwrap();
    assert_eq!(
        norito::json::from_slice::<AliasSetupPlanRequestV1>(&wire).unwrap(),
        quote.request
    );
}

#[test]
fn namespace_rejects_missing_time_wrong_policy_and_unavailable_one_year_term() {
    let mut policy = policy();
    let domain = DomainId::parse_fully_qualified("developer.universal").unwrap();
    let owner = steward_account();
    for (now, ttl) in [
        (0, Duration::from_secs(60)),
        (u64::MAX, Duration::from_secs(60)),
        (1, Duration::ZERO),
    ] {
        assert!(
            quote_domain(
                &policy,
                domain.clone(),
                DataSpaceId::UNIVERSAL,
                owner.clone(),
                now,
                ttl
            )
            .is_err()
        );
    }
    policy.min_term_years = 2;
    assert!(
        quote_domain(
            &policy,
            domain.clone(),
            DataSpaceId::UNIVERSAL,
            owner.clone(),
            1,
            Duration::from_secs(60)
        )
        .is_err()
    );
    policy.min_term_years = 1;
    policy.suffix_id = DATASPACE_ALIAS_SUFFIX_ID;
    assert!(
        quote_domain(
            &policy,
            domain,
            DataSpaceId::UNIVERSAL,
            owner,
            1,
            Duration::from_secs(60)
        )
        .is_err()
    );
}

#[test]
fn dynamic_dataspace_requires_exact_active_record_and_canonical_numeric_mapping() {
    let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, "builders").unwrap();
    let mut record = NameRecordV1::new(
        selector.clone(),
        steward_account(),
        Vec::new(),
        0,
        1,
        100,
        200,
        300,
        Metadata::default(),
    );
    assert_eq!(
        active_dataspace(&record, "builders", 50).unwrap(),
        DataSpaceId::from_hash(&selector.name_hash())
    );
    assert!(active_dataspace(&record, "different", 50).is_err());
    assert!(active_dataspace(&record, "builders", 100).is_err());
    record.name_hash[0] ^= 1;
    assert!(active_dataspace(&record, "builders", 50).is_err());
    record.name_hash = selector.name_hash();
    record.metadata.insert(
        "sns.dataspace_id".parse().unwrap(),
        iroha_primitives::json::Json::new(55_u64),
    );
    assert_eq!(
        active_dataspace(&record, "builders", 50).unwrap(),
        DataSpaceId::new(55)
    );
    record.metadata.insert(
        "sns.dataspace_id".parse().unwrap(),
        iroha_primitives::json::Json::new("55"),
    );
    assert!(active_dataspace(&record, "builders", 50).is_err());
    assert_eq!(catalog_dataspace(&[], "builders").unwrap(), None);
}

#[test]
fn static_catalog_rejects_conflicts_and_preserves_nondefault_ids() {
    let entry = |name: &str, id| NexusDataspaceCatalogStatus {
        alias: name.to_owned(),
        dataspace_id: id,
        ..NexusDataspaceCatalogStatus::default()
    };
    assert_eq!(
        catalog_dataspace(&[entry("builders", 7)], "builders").unwrap(),
        Some(DataSpaceId::new(7))
    );
    assert!(catalog_dataspace(&[entry("builders", 7), entry("builders", 8)], "builders").is_err());
    assert!(catalog_dataspace(&[entry("builders", 7), entry("other", 7)], "builders").is_err());
    assert_eq!(
        catalog_dataspace(&[entry("builders", 7), entry("builders", 7)], "builders").unwrap(),
        Some(DataSpaceId::new(7))
    );
}

fn dataspace_policy() -> SuffixPolicyV1 {
    let mut value = default_policy();
    value.suffix_id = DATASPACE_ALIAS_SUFFIX_ID;
    value.suffix = "dataspace".into();
    value.pricing[0].label_regex = "^[a-z]+$".into();
    value
}

fn account_policy() -> SuffixPolicyV1 {
    let mut value = default_policy();
    value.suffix_id = ACCOUNT_ALIAS_SUFFIX_ID;
    value.suffix = "account-alias".into();
    value.pricing[0].label_regex = "^[a-z]+@[a-z]+$".into();
    value
}

#[test]
fn private_owner_alias_binds_exact_dpn_name_hash_and_rejects_another_scope() {
    let alias = resolve_private_owner_alias("dpn", "admin").unwrap();
    assert_eq!(alias.canonical_text(), "admin@dpn");
    assert_eq!(
        alias.dataspace_id,
        DataSpaceId::from_hash(&private_dataspace_selector("dpn").unwrap().name_hash(),)
    );
    for label in ["", "Admin", " admin", "admin ", "admin@dpn", "admin@other"] {
        assert!(
            resolve_private_owner_alias("dpn", label).is_err(),
            "{label:?}"
        );
    }
    assert!(resolve_private_owner_alias("universal", "admin").is_err());
}

#[test]
fn private_dpn_quote_refuses_changed_account_scope_owner_expiry_and_policy() {
    let owner = steward_account();
    let alias = resolve_private_owner_alias("dpn", "admin").unwrap();
    let selector = NameSelectorV1 {
        version: NameSelectorV1::VERSION,
        suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
        label: alias.canonical_text(),
    };
    let record = NameRecordV1::new(
        selector,
        owner.clone(),
        vec![],
        0,
        1,
        10_000,
        20_000,
        30_000,
        Metadata::default(),
    );
    let quote = |account_alias, record: Option<&NameRecordV1>, policy: &SuffixPolicyV1| {
        quote_private_dataspace(
            &dataspace_policy(),
            &private_dataspace_selector("dpn").unwrap(),
            owner.clone(),
            1_000,
            Duration::from_secs(60),
            &[],
            None,
            policy,
            account_alias,
            record,
        )
    };
    let paid = quote(alias.clone(), Some(&record), &account_policy()).unwrap();
    assert_eq!(paid.dataspace.canonical_name.as_ref(), "dpn");
    assert_eq!(paid.account_alias.canonical_text(), "admin@dpn");
    assert_eq!(paid.request.intents.len(), 2);
    assert_eq!(paid.rent, "1".parse().unwrap());
    assert!(
        quote(
            resolve_private_owner_alias("other", "admin").unwrap(),
            None,
            &account_policy()
        )
        .is_err()
    );
    for mutation in 0..4 {
        let mut changed = record.clone();
        match mutation {
            0 => changed.owner = iroha_test_samples::gen_account_in("foreign").0,
            1 => changed.expires_at_ms = 1_000,
            2 => changed.ownership_generation = 0,
            _ => changed.name_hash = [0; 32],
        }
        assert!(quote(alias.clone(), Some(&changed), &account_policy()).is_err());
    }
    let mut wrong = account_policy();
    wrong.suffix_id = DATASPACE_ALIAS_SUFFIX_ID;
    assert!(quote(alias.clone(), None, &wrong).is_err());
    wrong = account_policy();
    wrong.min_term_years = 2;
    assert!(quote(alias.clone(), None, &wrong).is_err());
    wrong = account_policy();
    let mut currency = [41; 16];
    currency[6] = 0x49;
    currency[8] = 0x89;
    wrong.payment_asset_id = AssetDefinitionId::from_uuid_bytes(currency)
        .unwrap()
        .to_string();
    assert!(quote(alias, None, &wrong).is_err());
}

#[test]
fn private_dataspace_quote_pays_dataspace_and_owner_alias_without_parent_catalog_changes() {
    let policy = dataspace_policy();
    let selector = private_dataspace_selector("builders").unwrap();
    let owner = steward_account();
    let quote = quote_private_dataspace(
        &policy,
        &selector,
        owner.clone(),
        1_000,
        Duration::from_secs(60),
        &[],
        None,
        &account_policy(),
        resolve_private_owner_alias("builders", "admin").unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(
        quote.dataspace.dataspace_id,
        DataSpaceId::from_hash(&selector.name_hash())
    );
    assert_eq!(quote.dataspace.canonical_name.as_ref(), "builders");
    assert_eq!(quote.valid_until_ms, 61_000);
    assert_eq!(quote.rent, "1".parse().unwrap());
    assert_eq!(quote.account_alias.canonical_text(), "admin@builders");
    assert_eq!(
        quote.account_alias.dataspace_id,
        quote.dataspace.dataspace_id
    );
    assert_eq!(quote.request.intents.len(), 2);
    let intent = &quote.request.intents[0];
    assert!(
        matches!(&intent.intent, AliasIntentV1::Dataspace(value) if value.owner == owner && value.dataspace == quote.dataspace)
    );
    assert_eq!(intent.acquisition.term_years, 1);
    assert_eq!(
        intent.quote_guard.expected_payment_asset,
        quote.payment_asset
    );
    assert_eq!(intent.quote_guard.max_amount, "0.5".parse().unwrap());
    assert_eq!(
        intent.quote_guard.expected_policy_version,
        policy.policy_version
    );
    assert_eq!(intent.quote_guard.valid_until_ms, quote.valid_until_ms);
    let account_intent = &quote.request.intents[1];
    assert!(
        matches!(&account_intent.intent, AliasIntentV1::AccountAlias(value)
        if value.alias == quote.account_alias && value.target_account == owner
        && value.provision == AccountProvisionV1::Existing
        && value.role == AccountAliasRoleV1::Additional)
    );
    assert_eq!(account_intent.acquisition.term_years, 1);
    assert_eq!(
        account_intent.quote_guard.expected_payment_asset,
        quote.payment_asset
    );
    assert_eq!(
        account_intent.quote_guard.max_amount,
        "0.5".parse().unwrap()
    );
    assert_eq!(
        account_intent.quote_guard.valid_until_ms,
        quote.valid_until_ms
    );
    let wire = norito::json::to_vec(&quote.request).unwrap();
    assert_eq!(
        norito::json::from_slice::<AliasSetupPlanRequestV1>(&wire).unwrap(),
        quote.request
    );
    let existing = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![],
        0,
        1,
        10_000,
        20_000,
        30_000,
        Metadata::default(),
    );
    assert!(
        quote_private_dataspace(
            &policy,
            &selector,
            owner,
            1_000,
            Duration::from_secs(60),
            &[],
            Some(&existing),
            &account_policy(),
            resolve_private_owner_alias("builders", "admin").unwrap(),
            None,
        )
        .is_ok()
    );
}

#[test]
fn private_dataspace_quote_refuses_reserved_aliases_physical_scopes_and_changed_ownership() {
    for alias in [
        "universal",
        "Builders",
        " builders",
        "builders ",
        "a.b",
        "",
        "a@b",
    ] {
        assert!(private_dataspace_selector(alias).is_err(), "{alias:?}");
    }
    let policy = dataspace_policy();
    let selector = private_dataspace_selector("builders").unwrap();
    let id = DataSpaceId::from_hash(&selector.name_hash());
    let owner = steward_account();
    let quote = |policy: &SuffixPolicyV1,
                 now,
                 ttl,
                 catalog: &[NexusDataspaceCatalogStatus],
                 record: Option<&NameRecordV1>| {
        quote_private_dataspace(
            policy,
            &selector,
            owner.clone(),
            now,
            ttl,
            catalog,
            record,
            &account_policy(),
            resolve_private_owner_alias("builders", "admin").unwrap(),
            None,
        )
    };
    for catalog in [
        vec![NexusDataspaceCatalogStatus {
            alias: "builders".into(),
            dataspace_id: 7,
            ..Default::default()
        }],
        vec![NexusDataspaceCatalogStatus {
            alias: "other".into(),
            dataspace_id: id.as_u64(),
            ..Default::default()
        }],
    ] {
        assert!(quote(&policy, 1_000, Duration::from_secs(60), &catalog, None).is_err());
    }
    for (now, ttl) in [
        (0, Duration::from_secs(60)),
        (u64::MAX, Duration::from_secs(60)),
        (1, Duration::ZERO),
    ] {
        assert!(quote(&policy, now, ttl, &[], None).is_err());
    }
    let original = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![],
        0,
        1,
        10_000,
        20_000,
        30_000,
        Metadata::default(),
    );
    for mutation in 0..4 {
        let mut record = original.clone();
        match mutation {
            0 => record.owner = iroha_test_samples::gen_account_in("foreign").0,
            1 => record.expires_at_ms = 1_000,
            2 => record.ownership_generation = 0,
            3 => {
                record.metadata.insert(
                    "sns.dataspace_id".parse().unwrap(),
                    iroha_primitives::json::Json::new(7_u64),
                );
            }
            _ => unreachable!(),
        }
        assert!(quote(&policy, 1_000, Duration::from_secs(60), &[], Some(&record)).is_err());
    }
    let mut wrong = policy.clone();
    wrong.suffix_id = DOMAIN_NAME_SUFFIX_ID;
    assert!(quote(&wrong, 1_000, Duration::from_secs(60), &[], None).is_err());
    wrong = policy;
    wrong.min_term_years = 2;
    assert!(quote(&wrong, 1_000, Duration::from_secs(60), &[], None).is_err());
}

#[test]
fn private_dataspace_preparation_does_not_dispatch_after_deadline_or_for_invalid_alias() {
    let (account, key) = iroha_test_samples::gen_account_in("tests");
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"namespace deadline fixture",
        )),
    );
    let table = toml::toml! {
        chain = "namespace-deadline"
        network_id = (network.to_string())
        torii_url = "https://unreachable.invalid/"
        [account]
        chain_discriminant = 753
        public_key = (key.public_key().to_string())
        private_key = (iroha_crypto::ExposedPrivateKey(key.private_key().clone()).to_string())
    };
    let config = Config::load_table("namespace-tests.toml", table).unwrap();
    assert_eq!(config.account, account);
    let error = prepare_private_dataspace_request(&config, "builders", "admin", Instant::now())
        .unwrap_err();
    assert!(error.to_string().contains("deadline expired"));
    assert!(
        prepare_private_dataspace_request(
            &config,
            "universal",
            "admin",
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
}
