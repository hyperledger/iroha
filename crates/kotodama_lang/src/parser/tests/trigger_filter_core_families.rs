#[test]
fn parse_trigger_decl_with_structured_data_filters_for_core_families() {
    let account = sample_account_literal();
    let peer = "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D".to_string();
    let domain = "wonderland".to_string();
    let asset_definition = sample_asset_definition_literal();
    let nft = "n0$wonderland.universal".to_string();
    let rwa = format!(
        "{}$wonderland.universal",
        iroha_crypto::Hash::prehashed([7; iroha_crypto::Hash::LENGTH])
    );
    let trigger = "wake".to_string();
    let role = "auditor".to_string();
    let asset = {
        let account_id =
            iroha_data_model::account::AccountId::parse_encoded(&account).expect("account");
        let definition_id: iroha_data_model::asset::AssetDefinitionId =
            asset_definition.parse().expect("asset definition");
        iroha_data_model::asset::AssetId::new(definition_id, account_id).canonical_literal()
    };
    let cases = vec![
        (
            TriggerDataFamily::Peer,
            "added",
            vec![("peer".to_string(), peer)],
        ),
        (
            TriggerDataFamily::Domain,
            "created",
            vec![("domain".to_string(), domain)],
        ),
        (
            TriggerDataFamily::Account,
            "created",
            vec![("account".to_string(), account.clone())],
        ),
        (
            TriggerDataFamily::Asset,
            "added",
            vec![
                ("asset".to_string(), asset),
                ("asset_definition".to_string(), asset_definition.clone()),
            ],
        ),
        (
            TriggerDataFamily::AssetDefinition,
            "created",
            vec![("asset_definition".to_string(), asset_definition)],
        ),
        (
            TriggerDataFamily::Nft,
            "created",
            vec![("nft".to_string(), nft)],
        ),
        (
            TriggerDataFamily::Rwa,
            "created",
            vec![("rwa".to_string(), rwa)],
        ),
        (
            TriggerDataFamily::Trigger,
            "created",
            vec![("trigger".to_string(), trigger)],
        ),
        (
            TriggerDataFamily::Role,
            "created",
            vec![("role".to_string(), role)],
        ),
        (TriggerDataFamily::Configuration, "changed", vec![]),
        (TriggerDataFamily::Executor, "upgraded", vec![]),
    ];
    for (family, event, expected_matchers) in cases {
        let family_literal = match family {
            TriggerDataFamily::Peer => "peer",
            TriggerDataFamily::Domain => "domain",
            TriggerDataFamily::Account => "account",
            TriggerDataFamily::Asset => "asset",
            TriggerDataFamily::AssetDefinition => "asset_definition",
            TriggerDataFamily::Nft => "nft",
            TriggerDataFamily::Rwa => "rwa",
            TriggerDataFamily::Trigger => "trigger",
            TriggerDataFamily::Role => "role",
            TriggerDataFamily::Configuration => "configuration",
            TriggerDataFamily::Executor => "executor",
        };
        let matcher_block = expected_matchers
            .iter()
            .map(|(key, value)| format!("                    {key} \"{value}\";\n"))
            .collect::<String>();
        let src = format!(
            r#"
                seiyaku C {{ permission Run;
                    kotoage fn run() authorize(Run) {{}}
                    trigger wake -> run {{
                        on data {family_literal} {event} {{
{matcher_block}                        }}
                    }}
                }}
                "#
        );
        let prog = parse(&src).expect("parse trigger decl");
        let trigger = prog
            .items
            .iter()
            .find_map(|item| match item {
                Item::Trigger(t) => Some(t),
                _ => None,
            })
            .expect("trigger present");
        let TriggerFilter::Data(TriggerDataFilter::Structured(filter)) = &trigger.filter else {
            panic!("expected structured data filter");
        };
        assert_eq!(filter.family, family);
        assert_eq!(filter.event, TriggerDataEventKind::Named(event.to_string()));
        let actual_matchers = filter
            .matchers
            .iter()
            .map(|matcher| (matcher.key.clone(), matcher.value.clone()))
            .collect::<Vec<_>>();
        assert_eq!(actual_matchers, expected_matchers);
    }
}
#[test]
fn parse_trigger_decl_with_pipeline_filter() {
    for (source_filter, expected_filter) in [
        ("transaction", TriggerPipelineFilter::TransactionApproved),
        (
            "transaction approved",
            TriggerPipelineFilter::TransactionApproved,
        ),
        ("block", TriggerPipelineFilter::BlockApproved),
        ("block approved", TriggerPipelineFilter::BlockApproved),
    ] {
        let src = format!(
            r#"
            seiyaku C {{ permission Run;
                kotoage fn run() authorize(Run) {{}}
                trigger wake -> run {{
                    on pipeline {source_filter};
                }}
            }}
            "#
        );
        let prog = parse(&src).expect("parse trigger decl");
        let trigger = prog
            .items
            .iter()
            .find_map(|item| match item {
                Item::Trigger(t) => Some(t),
                _ => None,
            })
            .expect("trigger present");
        assert_eq!(trigger.filter, TriggerFilter::Pipeline(expected_filter));
    }
}
