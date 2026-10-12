//! Taira configuration contracts using the production schema without node runtime inputs.

use std::collections::BTreeMap;

use iroha_config::base::toml::WriteExt as _;
use norito::json::Value;
use toml::Table;

#[test]
fn public_taira_templates_inherit_canonical_rate_budgets() {
    use iroha_config::{
        base::{env::MockEnv, read::ConfigReader, toml::TomlSource},
        parameters::user::Torii,
    };

    let taira: Table =
        toml::from_str(include_str!("../../../configs/soranexus/taira/config.toml")).unwrap();
    let profile: Table = toml::from_str(include_str!("../profiles/sora-nexus-v1.toml")).unwrap();
    for section in [&taira["torii"], &profile["policy"]["torii"]] {
        // Full templates deliberately omit deployment-owned faucet/onboarding
        // signing inputs. Parse their rate policy with a valid public bind address.
        let policy = section.as_table().unwrap();
        let mut section = Table::new();
        section.insert("address".into(), taira["torii"]["address"].clone());
        for field in [
            "preauth_rate_per_ip_per_sec",
            "preauth_burst_per_ip",
            "query_rate_per_authority_per_sec",
            "query_burst_per_authority",
            "tx_rate_per_authority_per_sec",
            "tx_burst_per_authority",
            "deploy_rate_per_origin_per_sec",
            "deploy_burst_per_origin",
        ] {
            if let Some(value) = policy.get(field) {
                section.insert(field.into(), value.clone());
            }
        }
        let parsed = ConfigReader::new()
            .with_env(MockEnv::default())
            .with_toml_source(TomlSource::inline(section))
            .read_and_complete::<Torii>()
            .expect("public Torii rate policy inherits current defaults");
        // Torii::parse supplies the canonical defaults to omitted optional
        // budgets. The minimal-config regression covers that effective parser;
        // these public templates must not shadow its policy with stale values.
        for configured in [
            parsed.preauth_rate_per_ip_per_sec,
            parsed.preauth_burst_per_ip,
            parsed.query_rate_per_authority_per_sec,
            parsed.query_burst_per_authority,
            parsed.tx_rate_per_authority_per_sec,
            parsed.tx_burst_per_authority,
            parsed.deploy_rate_per_origin_per_sec,
            parsed.deploy_burst_per_origin,
        ] {
            assert_eq!(
                configured, None,
                "public template must inherit rate defaults"
            );
        }
    }
}

#[test]
fn lane_descriptor_collection_defaults_match_config_defaults() {
    use iroha_config::{
        base::{env::MockEnv, read::ConfigReader, toml::TomlSource},
        parameters::user::{ConfidentialComputeDescriptor, LaneDescriptor},
    };

    for explicit_collections in [false, true] {
        let mut confidential = Table::new()
            .write("mechanism", "encryption")
            .write("key_version", 1_i64);
        let expected_audiences = if explicit_collections {
            vec!["operator".to_owned(), "auditor".to_owned()]
        } else {
            Vec::new()
        };
        if explicit_collections {
            confidential = confidential.write(
                "allowed_audiences",
                toml::Value::Array(
                    expected_audiences
                        .iter()
                        .cloned()
                        .map(toml::Value::String)
                        .collect(),
                ),
            );
        }
        let direct_confidential = ConfigReader::new()
            .with_env(MockEnv::default())
            .with_toml_source(TomlSource::inline(confidential.clone()))
            .read_and_complete::<ConfidentialComputeDescriptor>()
            .expect("read confidential policy directly");
        let mut lane = Table::new()
            .write("index", 0_i64)
            .write("alias", "private")
            .write("confidential_compute", confidential);
        let expected_metadata = if explicit_collections {
            lane = lane.write("metadata", Table::new().write("operator_label", "test"));
            BTreeMap::from([("operator_label".to_owned(), "test".to_owned())])
        } else {
            BTreeMap::new()
        };
        let direct_lane = ConfigReader::new()
            .with_env(MockEnv::default())
            .with_toml_source(TomlSource::inline(lane.clone()))
            .read_and_complete::<LaneDescriptor>()
            .expect("read lane directly");
        let catalog_json =
            iroha_config::base::toml::value_to_json(&toml::Value::Array(vec![toml::Value::Table(
                lane,
            )]))
            .expect("convert catalog TOML to JSON");
        let mut catalog: Vec<LaneDescriptor> = norito::json::from_value(catalog_json)
            .expect("read lane catalog through collection JSON decoding");
        assert_eq!(catalog.len(), 1);
        let catalog_lane = catalog.pop().expect("one catalog lane");
        assert_eq!(direct_lane.metadata, expected_metadata);
        assert_eq!(catalog_lane.metadata, expected_metadata);
        assert_eq!(direct_confidential.allowed_audiences, expected_audiences);
        for lane in [direct_lane, catalog_lane] {
            assert_eq!(lane.index, Some(0));
            assert_eq!(lane.alias.as_deref(), Some("private"));
            let policy = lane.confidential_compute.expect("confidential lane policy");
            assert_eq!(policy.mechanism, direct_confidential.mechanism);
            assert_eq!(policy.key_version, Some(1));
            assert_eq!(policy.allowed_audiences, expected_audiences);
        }
    }
}
#[test]
fn lane_descriptor_collection_defaults_reject_malformed_values() {
    use iroha_config::parameters::user::LaneDescriptor;

    for catalog in [
        r#"[{"alias":"private","metadata":null}]"#,
        r#"[{"alias":"private","metadata":[]}]"#,
        r#"[{"alias":"private","metadata":"invalid"}]"#,
        r#"[{"alias":"private","metadata":{"operator_label":1}}]"#,
        r#"[{"alias":"private","confidential_compute":{"mechanism":"encryption","key_version":1,"allowed_audiences":null}}]"#,
        r#"[{"alias":"private","confidential_compute":{"mechanism":"encryption","key_version":1,"allowed_audiences":"operator"}}]"#,
        r#"[{"alias":"private","confidential_compute":{"mechanism":"encryption","key_version":1,"allowed_audiences":{}}}]"#,
        r#"[{"alias":"private","confidential_compute":{"mechanism":"encryption","key_version":1,"allowed_audiences":[1]}}]"#,
        r#"[{"alias":"private","confidential_compute":{"mechanism":"encryption","key_version":1,"unknown_policy":true}}]"#,
    ] {
        assert!(
            norito::json::from_json::<Vec<LaneDescriptor>>(catalog).is_err(),
            "collection defaults must not accept malformed configuration: {catalog}"
        );
        let value = norito::json::from_json::<Value>(catalog)
            .expect("malformed configuration is still valid JSON");
        assert!(
            norito::json::from_value::<Vec<LaneDescriptor>>(value).is_err(),
            "TOML collection decoding must reject malformed configuration: {catalog}"
        );
    }
}
#[test]
fn taira_profile_nexus_collections_deserialize_without_runtime_inputs() {
    use iroha_config::{
        base::{env::MockEnv, read::ConfigReader, toml::TomlSource},
        parameters::user::Nexus,
    };

    let mut profile: Table =
        toml::from_str(include_str!("../../../configs/soranexus/taira/config.toml"))
            .expect("checked-in Taira profile must be valid TOML");
    let nexus = profile
        .remove("nexus")
        .and_then(|value| value.as_table().cloned())
        .expect("Taira profile Nexus section");
    let nexus = ConfigReader::new()
        .with_env(MockEnv::default())
        .with_toml_source(TomlSource::inline(nexus))
        .read_and_complete::<Nexus>()
        .expect("Taira Nexus schema must load without runtime signing inputs");
    assert_eq!(nexus.lane_count.get(), 8);
    assert_eq!(nexus.lane_catalog.len(), 8);
    for (lane, (index, alias, teu_capacity)) in nexus.lane_catalog.iter().zip([
        (0, "core", None),
        (1, "governance", None),
        (2, "zk", None),
        (3, "dpn", None),
        (4, "is2", None),
        (5, "bpng", None),
        (6, "cbsi", None),
        (7, "is", None),
    ]) {
        assert_eq!(lane.index, Some(index));
        assert_eq!(lane.alias.as_deref(), Some(alias));
        assert!(lane.metadata.is_empty(), "Taira lane {index} metadata");
        assert_eq!(lane.scheduler.is_some(), teu_capacity.is_some());
        assert_eq!(
            lane.scheduler.and_then(|scheduler| scheduler.teu_capacity),
            teu_capacity
        );
        assert!(
            lane.scheduler
                .and_then(|scheduler| scheduler.starvation_bound_slots)
                .is_none()
        );
    }
    assert_eq!(nexus.dataspace_catalog.len(), 6);
    assert_eq!(
        nexus
            .dataspace_catalog
            .iter()
            .map(|dataspace| dataspace.alias.as_deref())
            .collect::<Vec<_>>(),
        ["universal", "dpn", "is2", "bpng", "cbsi", "is"].map(Some),
    );
    assert_eq!(nexus.routing_policy.rules.len(), 6);
    assert_eq!(
        nexus.governance.modules["parliament"].params,
        BTreeMap::from([
            ("selection".to_owned(), "multibody_sortition".to_owned()),
            ("approval_flow".to_owned(), "jit".to_owned()),
        ])
    );
}
#[test]
fn nexus_routing_and_governance_collection_defaults_match_config_defaults() {
    use iroha_config::{
        base::{
            env::MockEnv,
            read::{ConfigReader, ReadConfig},
            toml::TomlSource,
        },
        parameters::user::{GovernanceModule, RoutingPolicy, RoutingRule},
    };

    fn read<T: ReadConfig>(table: Table) -> T {
        ConfigReader::new()
            .with_env(MockEnv::default())
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<T>()
            .expect("read Nexus descriptor directly")
    }
    fn read_json<T: norito::json::JsonDeserialize>(value: &toml::Value) -> T {
        norito::json::from_value(
            iroha_config::base::toml::value_to_json(value).expect("convert Nexus TOML"),
        )
        .expect("read Nexus descriptor through collection JSON decoding")
    }
    fn reject_json<T: norito::json::JsonDeserialize>(json: &str) {
        assert!(
            norito::json::from_json::<T>(json).is_err(),
            "accepted {json}"
        );
        let value = norito::json::from_json::<Value>(json).expect("valid JSON fixture");
        assert!(
            norito::json::from_value::<T>(value).is_err(),
            "accepted {json}"
        );
    }

    for (include_rule, include_matcher) in [(false, false), (true, false), (true, true)] {
        let mut rule = Table::new().write("lane", 1_i64);
        if include_matcher {
            rule = rule.write("matcher", Table::new().write("account", "*@universal"));
        }
        let direct_rule = read::<RoutingRule>(rule.clone());
        let mut policy = Table::new().write("default_lane", 0_i64);
        if include_rule {
            policy = policy.write("rules", toml::Value::Array(vec![toml::Value::Table(rule)]));
        }
        let direct_policy = read::<RoutingPolicy>(policy.clone());
        let json_policy = read_json::<RoutingPolicy>(&toml::Value::Table(policy));
        for policy in [direct_policy, json_policy] {
            assert_eq!(policy.default_lane, Some(0));
            assert_eq!(policy.rules.len(), usize::from(include_rule));
            for rule in policy.rules.iter().chain(std::iter::once(&direct_rule)) {
                assert_eq!(rule.lane, Some(1));
                assert_eq!(
                    rule.matcher.account.as_deref(),
                    include_matcher.then_some("*@universal")
                );
                assert!(rule.matcher.instruction.is_none());
                assert!(rule.matcher.description.is_none());
            }
        }
    }
    for include_params in [false, true] {
        let mut module = Table::new().write("module_type", "parliament_sortition_jit");
        let expected_params = if include_params {
            module = module.write(
                "params",
                Table::new().write("selection", "multibody_sortition"),
            );
            BTreeMap::from([("selection".to_owned(), "multibody_sortition".to_owned())])
        } else {
            BTreeMap::new()
        };
        let direct_module = read::<GovernanceModule>(module.clone());
        let mut modules = read_json::<BTreeMap<String, GovernanceModule>>(&toml::Value::Table(
            Table::new().write("parliament", module),
        ));
        for module in [
            direct_module,
            modules.remove("parliament").expect("governance module"),
        ] {
            assert_eq!(
                module.module_type.as_deref(),
                Some("parliament_sortition_jit")
            );
            assert_eq!(module.params, expected_params);
        }
    }
    for json in [
        r#"{"rules":null}"#,
        r#"{"rules":{}}"#,
        r#"{"rules":"invalid"}"#,
    ] {
        reject_json::<RoutingPolicy>(json);
    }
    for json in [
        r#"[{"matcher":null}]"#,
        r#"[{"matcher":[]}]"#,
        r#"[{"matcher":"invalid"}]"#,
    ] {
        reject_json::<Vec<RoutingRule>>(json);
    }
    for json in [
        r#"{"parliament":{"params":null}}"#,
        r#"{"parliament":{"params":[]}}"#,
        r#"{"parliament":{"params":"invalid"}}"#,
        r#"{"parliament":{"params":{"selection":1}}}"#,
    ] {
        reject_json::<BTreeMap<String, GovernanceModule>>(json);
    }
}
