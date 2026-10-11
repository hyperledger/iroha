// Source-equivalence tests for application routed-read materialization.
use iroha_data_model::Registrable as _;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::RoutedReadSourceFixture")]
#[derive(
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    crate::json_macros::JsonSerialize,
)]

struct RoutedReadSourceFixture {
    id: String,
    metadata: Vec<String>,
    optional: Option<String>,
}
#[test]
fn routed_read_source_accepts_only_canonical_uaid_literals() {
    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let canonical = format!("uaid:{HEX}");
    assert!(parse_torii_space_directory_uaid_literal(&canonical).is_ok());
    for literal in [
        HEX.to_owned(),
        format!("UAID:{HEX}"),
        format!("uaid:{}", HEX.to_uppercase()),
        format!(" {canonical}"),
        format!("{canonical} "),
    ] {
        assert!(
            parse_torii_space_directory_uaid_literal(&literal).is_err(),
            "noncanonical routed-read UAID must reject: {literal:?}"
        );
    }
}
#[test]
fn routed_read_borrowed_struct_is_wire_equivalent_to_owned_target() {
    let owned = RoutedReadSourceFixture {
        id: "alice".to_owned(),
        metadata: vec!["one".to_owned(), "two".to_owned()],
        optional: Some("present".to_owned()),
    };
    let source = ToriiBorrowedRoutedReadStruct::<RoutedReadSourceFixture, 3>::new([
        &owned.id,
        &owned.metadata,
        &owned.optional,
    ]);
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let expected = crate::frame_test_support::assert_current_frame(
        &owned,
        "iroha_torii::RoutedReadSourceFixture",
    );
    type Source = ToriiBorrowedRoutedReadStruct<'static, RoutedReadSourceFixture, 3>;
    assert_eq!(
        <Source as norito::NoritoSchema>::nominal_name(),
        "iroha_torii::ToriiBorrowedRoutedReadStruct<'_, iroha_torii::RoutedReadSourceFixture, 3>",
    );
    assert_eq!(
        <Source as norito::NoritoSchema>::frame_name(),
        <RoutedReadSourceFixture as norito::NoritoSchema>::frame_name(),
    );
    let actual = norito::core::to_bytes_bounded(&source, expected.len())
        .expect("borrowed fixture fits its exact canonical boundary");
    assert_eq!(actual, expected);
    let decoded: RoutedReadSourceFixture = norito::decode_canonical(&actual)
        .expect("borrowed source decodes through the actual owned target");
    assert_eq!(decoded, owned);
    assert!(norito::core::to_bytes_bounded(&source, expected.len() - 1).is_err());
}
#[test]
fn routed_read_source_payload_owns_only_after_bounded_decode() {
    let owned = RoutedReadSourceFixture {
        id: "alice".to_owned(),
        metadata: vec!["one".to_owned(), "two".to_owned()],
        optional: None,
    };
    let source = ToriiBorrowedRoutedReadStruct::<RoutedReadSourceFixture, 3>::new([
        &owned.id,
        &owned.metadata,
        &owned.optional,
    ]);
    let phase = 64 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits source materialization");
    let payload = torii_bounded_routed_read_source_payload::<RoutedReadSourceFixture, _>(
        &source,
        &mut budget,
    )
    .expect("small borrowed source materializes inside the ledger");
    assert_eq!(payload.value, owned);
    assert_eq!(
        budget.retained_canonical_bytes,
        payload.canonical_bytes.capacity()
    );
    assert!(budget.retained_decoded_bytes > 0);
}
#[test]
fn asset_definition_borrowed_json_matches_owned_projection_at_exact_cap() {
    let authority = crate::tests_runtime_handlers::checked_torii_test_account_id(
        0x71,
        "derive routed asset-definition source fixture",
    );
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id,
        "usd".parse().expect("asset name"),
    );
    let mut definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id,
        "Treasury USD".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .with_description(Some("settlement token".to_owned()))
    .build(&authority);
    let binding = iroha_core::state::AssetDefinitionAliasBindingRecord {
        alias: "usd#issuer.main".parse().expect("asset alias"),
        lease_expiry_ms: Some(50),
        grace_until_ms: Some(75),
        bound_at_ms: 10,
    };
    let observation_time_ms = 60;
    use iroha_data_model::asset::definition::{
        AssetConfidentialPolicy, ConfidentialPolicyMode, ConfidentialPolicyTransition,
    };
    let transition = ConfidentialPolicyTransition {
        new_mode: ConfidentialPolicyMode::ShieldedOnly,
        effective_height: 80,
        previous_mode: ConfidentialPolicyMode::Convertible,
        transition_id: iroha_crypto::Hash::new(b"source-equivalence transition"),
        conversion_window: Some(20),
    };
    let configured = AssetConfidentialPolicy {
        mode: ConfidentialPolicyMode::Convertible,
        vk_set_hash: Some(iroha_crypto::Hash::new(
            b"source-equivalence verifying keys",
        )),
        poseidon_params_id: Some(3),
        pedersen_params_id: Some(5),
        pending_transition: Some(transition),
    };
    for policy in [
        AssetConfidentialPolicy::default(),
        configured,
        AssetConfidentialPolicy {
            pending_transition: Some(ConfidentialPolicyTransition {
                conversion_window: None,
                ..transition
            }),
            ..configured
        },
    ] {
        definition.confidential_policy = policy;
        for alias_binding in [None, Some(&binding)] {
            let source = ToriiAssetDefinitionJsonSource {
                definition: &definition,
                owning_dataspace: None,
                alias_binding,
                observation_time_ms,
            };
            let mut expected_value = norito::json::to_value(&definition).expect("definition JSON");
            if let norito::json::Value::Object(object) = &mut expected_value {
                object.insert("owning_dataspace".into(), norito::json::Value::Null);
            }
            if let Some(binding) = alias_binding {
                let binding_dto = routing::asset_alias_binding_dto(binding, observation_time_ms);
                let norito::json::Value::Object(expected_object) = &mut expected_value else {
                    panic!("asset definition must serialize as an object");
                };
                expected_object.insert(
                    "alias".into(),
                    norito::json::Value::from(binding.alias.to_string()),
                );
                expected_object.insert(
                    "alias_binding".into(),
                    norito::json::to_value(&binding_dto).expect("alias-binding JSON"),
                );
            }
            let expected = norito::json::to_json_bounded_boxed(&expected_value, usize::MAX)
                .expect("owned projection has a compact encoding");
            let actual = norito::json::to_json_bounded_boxed(&source, expected.len())
                .expect("borrowed projection fits its exact boundary");
            assert_eq!(actual, expected);
            assert_eq!(
                norito::json::to_json_bounded_boxed(&source, expected.len() - 1),
                Err(norito::json::BoundedJsonError::BodyTooLarge)
            );
        }
    }
}

#[test]
fn asset_definition_source_lookup_never_calls_cloning_world_accessor() {
    let source = include_str!("../../torii_app_routed_read_source.rs");
    let start = source
        .find("fn resolve_torii_asset_definition_source_selector")
        .expect("bounded selector helper remains present");
    let end = source[start..]
        .find("fn execute_torii_asset_definition_local_source_read")
        .map(|offset| start + offset)
        .expect("bounded local source helper remains present");
    let selector = &source[start..end];
    assert!(selector.contains(".asset_definitions()"));
    assert!(!selector.contains(".asset_definition("));
    assert!(source.contains("ToriiAssetDefinitionJsonSource"));
}
#[test]
fn space_directory_bindings_borrowed_json_matches_canonical_shape() {
    let uaid: iroha_data_model::nexus::UniversalAccountId =
        "uaid:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            .parse()
            .expect("UAID");
    let source = ToriiSpaceDirectoryBindingsJsonSource {
        uaid: &uaid,
        bindings: None,
        catalog: &iroha_data_model::nexus::DataSpaceCatalog::default(),
        visibility: &routing::DataspaceReadVisibility::all_for_tests(),
    };
    let expected = norito::json::to_json_bounded_boxed(
        &norito::json!({ "dataspaces": [], "uaid": (uaid.to_string()) }),
        usize::MAX,
    )
    .expect("canonical empty binding response");
    let actual = norito::json::to_json_bounded_boxed(&source, expected.len())
        .expect("borrowed empty response fits exact boundary");
    assert_eq!(actual, expected);
    assert_eq!(
        norito::json::to_json_bounded_boxed(&source, expected.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
}
#[test]
fn space_directory_binding_source_does_not_clone_nexus_catalog() {
    let source = include_str!("../../torii_app_routed_read_source.rs");
    let start = source
        .find("fn execute_torii_space_directory_bindings_local_source_read")
        .expect("bounded space-directory source helper remains present");
    let end = source[start..]
        .find("fn torii_bounded_local_proof_record_payload")
        .map(|offset| start + offset)
        .expect("next source helper remains present");
    let helper = &source[start..end];
    assert!(helper.contains("world.dataspace_catalog()"));
    assert!(!helper.contains("nexus_snapshot"));
    assert!(source.contains("account_id.json_serialize_to(output)"));
}
#[test]
fn contract_alias_borrowed_json_matches_owned_dto_at_exact_cap() {
    let authority = crate::tests_runtime_handlers::checked_torii_test_account_id(
        0x72,
        "derive routed contract-alias source fixture",
    );
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical network id"),
        &authority,
        0,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    let contract_alias: iroha_data_model::smart_contract::ContractAlias =
        "router::dex.universal".parse().expect("contract alias");
    let contract_subject = contract_address.subject_id();
    let binding = iroha_core::state::ContractAliasBindingRecord {
        alias: contract_alias.clone(),
        lease_expiry_ms: Some(50),
        grace_until_ms: Some(75),
        bound_at_ms: 10,
    };
    let observation_time_ms = 60;
    let source = ToriiContractAliasJsonSource {
        contract_alias: &contract_alias,
        contract_address: &contract_address,
        contract_subject: &contract_subject,
        dataspace_alias: "universal",
        binding: &binding,
        observation_time_ms,
    };
    let expected_dto = routing::ContractAliasResolveResponseDto {
        contract_alias: contract_alias.to_string(),
        contract_address: contract_address.to_string(),
        contract_subject_account: contract_subject.to_string(),
        dataspace: "universal".to_owned(),
        contract_alias_binding: routing::contract_alias_binding_dto(&binding, observation_time_ms),
        source: "world_state".to_owned(),
    };
    let expected = norito::json::to_json_bounded_boxed(&expected_dto, usize::MAX)
        .expect("owned DTO has a compact encoding");
    let actual = norito::json::to_json_bounded_boxed(&source, expected.len())
        .expect("borrowed contract alias fits exact boundary");
    assert_eq!(actual, expected);
    assert_eq!(
        norito::json::to_json_bounded_boxed(&source, expected.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
}
#[test]
fn contract_alias_source_borrows_subject_and_dataspace_catalog() {
    let source = include_str!("../../torii_app_routed_read_source.rs");
    let start = source
        .find("fn execute_torii_contract_alias_local_source_read")
        .expect("bounded contract-alias source helper remains present");
    let end = source[start..]
        .find("fn torii_bounded_local_proof_record_payload")
        .map(|offset| start + offset)
        .expect("next source helper remains present");
    let helper = &source[start..end];
    assert!(helper.contains("borrow_bound_contract_subject_from_world"));
    assert!(
        helper.contains("dataspace_id_for_alias_segment(app, contract_alias.dataspace_segment())")
    );
    assert!(!helper.contains("nexus_snapshot"));
    assert!(!helper.contains(".cloned()"));
}
#[test]
fn explorer_asset_definition_borrowed_json_matches_owned_dto_at_exact_cap() {
    let authority = crate::tests_runtime_handlers::checked_torii_test_account_id(
        0x73,
        "derive routed explorer asset-definition source fixture",
    );
    let domain_id =
        iroha_model_base::domain::DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        domain_id,
        "eur".parse().expect("asset name"),
    );
    let definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id,
        "Treasury EUR".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .with_description(Some("settlement reserve".to_owned()))
    .build(&authority);
    let source = ToriiExplorerAssetDefinitionJsonSource {
        definition: &definition,
        owning_dataspace: None,
        assets: 7,
        locked_quantity: None,
        circulating_quantity: None,
    };
    let expected_dto =
        crate::explorer::ExplorerAssetDefinitionDto::from_definition_with_asset_count(
            &definition,
            7,
            None,
        );
    let expected = norito::json::to_json_bounded_boxed(&expected_dto, usize::MAX)
        .expect("owned explorer DTO has a compact encoding");
    let actual = norito::json::to_json_bounded_boxed(&source, expected.len())
        .expect("borrowed explorer DTO fits its exact boundary");
    assert_eq!(actual, expected);
    assert_eq!(
        norito::json::to_json_bounded_boxed(&source, expected.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
}
#[test]
fn explorer_asset_definition_source_avoids_cloning_world_and_governance_snapshots() {
    let source = include_str!("../../torii_app_routed_read_source.rs");
    let start = source
        .find("fn execute_torii_explorer_asset_definition_local_source_read")
        .expect("bounded explorer asset-definition helper remains present");
    let end = source[start..]
        .find("fn torii_bounded_local_proof_record_payload")
        .map(|offset| start + offset)
        .expect("next source helper remains present");
    let helper = &source[start..end];
    assert!(helper.contains("world.asset_definitions().get(definition_id)"));
    assert!(
        helper
            .split_whitespace()
            .collect::<String>()
            .contains("world.assets_iter()")
    );
    assert!(!helper.contains(".asset_definition("));
    assert!(!helper.contains("governance_snapshot"));
    assert!(!helper.contains("AssetId::new"));
}
#[test]
fn routed_read_json_drops_canonical_scratch_before_final_encoding() {
    let source = include_str!("../../torii_app_routed_read_source.rs");
    let execute = include_str!("../../torii_app_routed_read_execute.rs");
    let merge = include_str!("../../torii_app_routed_read_merge.rs");
    assert!(source.contains("drop(canonical_bytes);\n            let body ="));
    assert!(execute.contains("drop(canonical_bytes);\n                    budget.json_response"));
    assert!(
        merge
            .matches("drop(canonical_bytes);\n                    budget.json_response")
            .count()
            >= 1
    );
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoutedReadSourceStatus {
    Proven,
    Residual,
}
fn routed_read_source_status(endpoint: ToriiReadEndpointV1) -> RoutedReadSourceStatus {
    use RoutedReadSourceStatus::{Proven, Residual};
    use ToriiReadEndpointV1::*;
    match endpoint {
        AccountGet
        | ProofRecordGet
        | AssetDefinitionGet
        | SpaceDirectoryBindingsGet
        | NexusPublicLaneValidators
        | AliasResolve
        | AliasResolveIndex
        | ContractAliasResolve
        | ExplorerAssetDefinitionDetail
        | ExplorerAssetDefinitionSnapshot
        | ContractStateGet
        | InternalAccountGet
        | InternalAccountAssetGet
        | ContractDeploymentState
        | AccountOnboardingCurrentState => Proven,
        ExplorerAccountDetail
        | AssetHoldersGet
        | AssetHoldersQuery
        | DomainsList
        | DomainsQuery
        | AccountAssetsGet
        | AccountAssetsQuery
        | AccountPermissionsGet
        | AccountTransactionsGet
        | AccountTransactionsQuery
        | TransactionsQuery
        | PipelineTransactionStatusGet
        | AccountsList
        | AccountsQuery
        | AccountsPortfolio
        | AssetDefinitionsList
        | AssetDefinitionsQuery
        | NftsList
        | NftsQuery
        | NexusPublicLaneStake
        | NexusPublicLaneRewards
        | NexusDataspacesAccountSummary
        | SpaceDirectoryManifestsGet
        | RwasList
        | RwasQuery
        | AliasLookupByAccount
        | ExplorerAssetDefinitionEconometrics
        | ContractViewPost
        | ContractViewBatchPost
        | AccountHistoryGet
        | InternalAccountTransactionGet
        | AccountPermissionsQuery
        | UaidManifestsQuery
        | AccountHistoryQuery => Residual,
    }
}
#[test]
fn routed_read_source_inventory_classifies_all_49_endpoints() {
    use ToriiReadEndpointV1::*;
    let endpoints = [
        AccountGet,
        ExplorerAccountDetail,
        AccountAssetsGet,
        AccountAssetsQuery,
        AccountPermissionsGet,
        AccountTransactionsGet,
        AccountTransactionsQuery,
        TransactionsQuery,
        PipelineTransactionStatusGet,
        ProofRecordGet,
        AccountsList,
        AccountsQuery,
        AccountsPortfolio,
        AssetDefinitionsList,
        AssetDefinitionGet,
        AssetDefinitionsQuery,
        AssetHoldersGet,
        AssetHoldersQuery,
        DomainsList,
        DomainsQuery,
        NftsList,
        NftsQuery,
        NexusPublicLaneValidators,
        NexusPublicLaneStake,
        NexusPublicLaneRewards,
        NexusDataspacesAccountSummary,
        SpaceDirectoryBindingsGet,
        SpaceDirectoryManifestsGet,
        RwasList,
        RwasQuery,
        AliasResolve,
        AliasResolveIndex,
        AliasLookupByAccount,
        ExplorerAssetDefinitionDetail,
        ExplorerAssetDefinitionEconometrics,
        ExplorerAssetDefinitionSnapshot,
        ContractAliasResolve,
        ContractStateGet,
        ContractViewPost,
        ContractViewBatchPost,
        AccountHistoryGet,
        InternalAccountGet,
        InternalAccountTransactionGet,
        InternalAccountAssetGet,
        ContractDeploymentState,
        AccountOnboardingCurrentState,
        AccountPermissionsQuery,
        UaidManifestsQuery,
        AccountHistoryQuery,
    ];
    let proven = endpoints
        .iter()
        .copied()
        .filter(|endpoint| routed_read_source_status(*endpoint) == RoutedReadSourceStatus::Proven)
        .count();
    assert_eq!(endpoints.len(), 49);
    // These collection paths now execute through collection_sources, rather
    // than the older DTO helpers whose isolated parity tests appear above.
    // Source certification requires the actual canonical engine path.
    assert_eq!(proven, 15);
    assert_eq!(endpoints.len() - proven, 34);
}
#[test]
fn routed_read_blanket_rejection_is_absent_repo_wide() {
    let forbidden = [
        "generic_app_route_source",
        "unsupported_generic_app_routed_response",
        "generic_app_routed_source_gate_tests",
        "assert_fixed_routed_rejection",
        "assert_generic_app_read_unsupported",
        "assert_fixed_generic_app_multiroute_rejection",
        "routed application reads are unavailable until source materialization, decoding, merging, and response encoding share one bounded memory envelope",
        "multi-route application reads are unavailable",
        "fixed multi-route rejection",
        "generic application-read gate",
        "local_nexus_read_fanout_rejects_before_recursive_self_proxying",
        "internal_torii_proxy_route_authenticates_before_generic_read_gate",
        "IROHA_TORII_LOCAL_READ_FANOUT_COORDINATOR",
        "local_read_fanout_coordinator_enabled",
    ];
    let mut pending = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).expect("read Torii source directory") {
            let entry = entry.expect("read Torii source entry");
            let path = entry.path();
            let file_type = entry.file_type().expect("read Torii source entry type");
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension() != Some(std::ffi::OsStr::new("rs"))
                || path.ends_with("tests/lib_routed_reads/routed_read_source_bounds.rs")
            {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read Torii Rust source");
            for rejected in forbidden {
                assert!(
                    !source.contains(rejected),
                    "obsolete routed-read gate `{rejected}` survives in {}",
                    path.display()
                );
            }
        }
    }
}
