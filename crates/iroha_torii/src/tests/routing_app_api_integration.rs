#[cfg(all(test, feature = "app_api"))]
#[allow(clippy::await_holding_lock)]
mod app_api_integration_tests {
    use super::*;
    use axum::Router;
    use http_body_util::BodyExt as _;
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use tower::ServiceExt;
    static APP_QUERY_LIMITS_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    fn app_query_limits_guard() -> MutexGuard<'static, ()> {
        APP_QUERY_LIMITS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn checked_app_api_keypair(
        seed: u8,
        algorithm: iroha_crypto::Algorithm,
        context: &'static str,
    ) -> iroha_crypto::KeyPair {
        checked_routing_fixture_keypair(seed, algorithm, context)
    }
    fn checked_app_api_account_id(seed: u8, context: &'static str) -> AccountId {
        AccountId::new(
            checked_app_api_keypair(seed, iroha_crypto::Algorithm::Ed25519, context)
                .public_key()
                .clone(),
        )
    }
    fn state_with_assets(
        domain_id: DomainId,
        authority: AccountId,
        accounts: Vec<AccountId>,
        asset_definitions: Vec<(AssetDefinitionId, String)>,
        assets: Vec<Asset>,
    ) -> Arc<State> {
        let domain = Domain::new(domain_id.clone()).build(&authority);
        let accounts: Vec<Account> = accounts
            .into_iter()
            .map(|id| Account::new(id.clone()).build(&authority))
            .collect();
        let asset_definitions: Vec<AssetDefinition> = asset_definitions
            .into_iter()
            .map(|(id, name)| {
                AssetDefinition::numeric(
                    id,
                    name,
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
                .build(&authority)
            })
            .collect();
        let world = World::with_assets([domain], accounts, asset_definitions, assets, []);
        Arc::new(iroha_core::state::State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ))
    }
    #[test]
    fn projected_account_assets_stream_scoped_rows_and_charge_skipped_candidates() {
        let _guard = app_query_limits_guard();
        let alice_id =
            checked_app_api_account_id(0x75, "derive projected account assets Alice fixture key");
        let bob_id =
            checked_app_api_account_id(0x76, "derive projected account assets Bob fixture key");
        let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
        let rose_def =
            AssetDefinitionId::derive_from_components(domain_id.clone(), "rose".parse().unwrap());
        let lily_def =
            AssetDefinitionId::derive_from_components(domain_id.clone(), "lily".parse().unwrap());
        let assets = vec![
            Asset::new(
                AssetId::new(rose_def.clone(), alice_id.clone()),
                Quantity::from(10_u32),
            ),
            Asset::new(
                AssetId::new(lily_def.clone(), alice_id.clone()),
                Quantity::from(7_u32),
            ),
            Asset::new(
                AssetId::new(rose_def.clone(), bob_id.clone()),
                Quantity::from(99_u32),
            ),
        ];
        let state = state_with_assets(
            domain_id,
            alice_id.clone(),
            vec![alice_id.clone(), bob_id],
            vec![
                (rose_def.clone(), "rose".to_owned()),
                (lily_def, "lily".to_owned()),
            ],
            assets,
        );
        let world = state.world_view();
        let scoped_accounts = vec![alice_id.clone()];
        let projected: Vec<_> = projected_account_assets(
            &world,
            &scoped_accounts,
            Some(&rose_def),
            None,
            &DataspaceReadVisibility::all_for_tests(),
        )
        .collect();
        assert_eq!(
            projected.len(),
            2,
            "the filtered balance still consumes scan work"
        );
        let projected: Vec<_> = projected.into_iter().flatten().collect();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].account_id, alice_id.to_string());
        assert_eq!(projected[0].asset, rose_def.to_string());
        assert_eq!(projected[0].quantity, Quantity::from(10_u32));
    }
    #[test]
    fn accumulate_asset_holder_quantity_respects_scope_filter() {
        let account_id =
            checked_app_api_account_id(0x77, "derive asset holder quantity fixture account key");
        let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
        let asset_def =
            AssetDefinitionId::derive_from_components(domain_id, "rose".parse().unwrap());
        let global_asset_id = AssetId::new(asset_def.clone(), account_id.clone());
        let scoped_asset_id = AssetId::with_scope(
            asset_def,
            account_id.clone(),
            AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
        );
        let scope_filter = AssetBalanceScope::Global;
        let mut map = BTreeMap::new();
        accumulate_asset_holder_quantity(
            &mut map,
            &global_asset_id,
            &Quantity::from(10_u32),
            Some(&scope_filter),
        )
        .expect("global holder quantity accumulation");
        accumulate_asset_holder_quantity(
            &mut map,
            &scoped_asset_id,
            &Quantity::from(99_u32),
            Some(&scope_filter),
        )
        .expect("filtered holder quantity accumulation");
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get(&(account_id, AssetBalanceScope::Global)),
            Some(&Quantity::from(10_u32))
        );
    }
    #[test]
    fn explorer_circulating_quantity_rejects_inconsistent_locked_supply() {
        use iroha_primitives::numeric::Quantity;
        assert_eq!(
            explorer_circulating_quantity(&Quantity::from(100_u32), &Quantity::from(40_u32))
                .expect("locked supply is within total"),
            Quantity::from(60_u32)
        );
        assert!(
            explorer_circulating_quantity(&Quantity::from(100_u32), &Quantity::from(101_u32))
                .is_err()
        );
    }
    #[tokio::test]
    async fn confidential_asset_transitions_reports_pending_window_metadata() {
        let _guard = app_query_limits_guard();
        use axum::routing::get;
        let alice_id = checked_app_api_account_id(
            0x85,
            "derive confidential asset transition fixture account key",
        );
        let vk_hash = Hash::new(b"vk-set-hash");
        let transition_id = Hash::new(b"transition-window");
        let expected_vk_hex = encode_hash_hex(&vk_hash);
        let expected_transition_hex = encode_hash_hex(&transition_id);
        let pending_transition =
            iroha_data_model::asset::definition::ConfidentialPolicyTransition {
                new_mode: iroha_data_model::asset::definition::ConfidentialPolicyMode::ShieldedOnly,
                previous_mode:
                    iroha_data_model::asset::definition::ConfidentialPolicyMode::Convertible,
                effective_height: 1_200,
                transition_id,
                conversion_window: Some(200),
            };
        let policy = iroha_data_model::asset::definition::AssetConfidentialPolicy {
            mode: iroha_data_model::asset::definition::ConfidentialPolicyMode::Convertible,
            vk_set_hash: Some(vk_hash),
            poseidon_params_id: Some(7),
            pedersen_params_id: Some(11),
            pending_transition: Some(pending_transition),
        };
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(&alice_id);
        let account = Account::new(alice_id.clone()).build(&alice_id);
        let mut asset_def = AssetDefinition::numeric(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            ),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&alice_id);
        asset_def.set_confidential_policy(policy);
        let asset_def_id = asset_def.id().clone();
        let expected_asset_id = asset_def_id.to_string();
        let world = World::with([domain], [account], [asset_def]);
        let state = Arc::new(iroha_core::state::State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        bind_permanent_asset_alias_for_test(
            &state,
            &alice_id,
            &asset_def_id,
            "rose#wonderland.universal",
        );
        let app = Router::new().route(
            "/v1/confidential/assets/{definition_id}/transitions",
            get({
                let state = state.clone();
                move |path: axum::extract::Path<String>| {
                    let state = state.clone();
                    async move { handle_v1_confidential_asset_transitions(state, path).await }
                }
            }),
        );
        let req = http::Request::builder()
            .method("GET")
            .uri("/v1/confidential/assets/rose%23wonderland.universal/transitions")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        assert_eq!(json["asset_id"].as_str(), Some(expected_asset_id.as_str()));
        assert_eq!(json["current_mode"].as_str(), Some("Convertible"));
        assert_eq!(json["effective_mode"].as_str(), Some("Convertible"));
        assert_eq!(json["vk_set_hash"].as_str(), Some(expected_vk_hex.as_str()));
        assert_eq!(json["poseidon_params_id"].as_u64(), Some(7));
        assert_eq!(json["pedersen_params_id"].as_u64(), Some(11));
        assert_eq!(
            json["pending_transition"]["transition_id"].as_str(),
            Some(expected_transition_hex.as_str())
        );
        assert_eq!(
            json["pending_transition"]["conversion_window"].as_u64(),
            Some(200)
        );
        assert_eq!(
            json["pending_transition"]["window_open_height"].as_u64(),
            Some(1_000)
        );
        assert_eq!(
            json["pending_transition"]["new_mode"].as_str(),
            Some("ShieldedOnly")
        );
        assert!(json["block_height"].as_u64().is_some());
    }
    #[tokio::test]
    async fn confidential_asset_transitions_rejects_prefixed_path_selector() {
        let _guard = app_query_limits_guard();
        let (state, _, _) = build_asset_holder_fixture_state();
        let result = handle_v1_confidential_asset_transitions(
            state,
            axum::extract::Path("prefix:550e8400e29b41d4a7164466554400dd".to_string()),
        )
        .await;
        match result {
            Err(Error::Query(iroha_data_model::ValidationFail::NotPermitted(_))) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("prefixed selector must be rejected"),
        }
    }
    #[tokio::test]
    async fn get_parameters_returns_json() {
        let _guard = app_query_limits_guard();
        use axum::routing::get;
        use iroha_core::{kura::Kura, query::store::LiveQueryStore};
        let state = Arc::new(iroha_core::state::State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let app = Router::new().route(
            "/v1/parameters",
            get({
                let state = state.clone();
                move || async move { handle_v1_parameters(state.clone()).await }
            }),
        );
        let req = http::Request::builder()
            .method("GET")
            .uri("/v1/parameters")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        let json: norito::json::Value = norito::json::from_str(&s).unwrap();
        assert!(json.get("sumeragi").is_some());
        assert!(json.get("block").is_some());
        assert!(json.get("transaction").is_some());
    }
    fn build_asset_holder_fixture_state() -> (Arc<iroha_core::state::State>, AccountId, AccountId) {
        let alice_id = checked_app_api_account_id(0x86, "derive asset holder fixture Alice key");
        let bob_id = checked_app_api_account_id(0x87, "derive asset holder fixture Bob key");
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let rose_def: AssetDefinitionId =
            test_asset_definition_id_from_hex("550e8400e29b41d4a7164466554400dd");
        let rose_definition = AssetDefinition::numeric(
            rose_def.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&alice_id);
        let assets = vec![
            Asset::new(
                AssetId::new(rose_def.clone(), alice_id.clone()),
                Quantity::from(10_u32),
            ),
            Asset::new(
                AssetId::new(rose_def.clone(), bob_id.clone()),
                Quantity::from(20_u32),
            ),
        ];
        let domain = Domain::new(domain_id.clone()).build(&alice_id);
        let alice_account = Account::new(alice_id.clone()).build(&alice_id);
        let bob_account = Account::new(bob_id.clone()).build(&alice_id);
        let mut world = World::with_assets(
            [domain],
            [alice_account, bob_account],
            [rose_definition],
            assets,
            [],
        );
        install_asset_holder_alias_parent_leases_for_test(
            &mut world,
            &alice_id,
            "universal",
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            &[&domain_id],
        );
        let state = Arc::new(iroha_core::state::State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        bind_permanent_asset_alias_for_test(
            &state,
            &alice_id,
            &rose_def,
            "rose#wonderland.universal",
        );
        bind_account_alias_for_test(&state, &alice_id, "treasury@universal");
        (state, alice_id, bob_id)
    }
    fn install_asset_holder_alias_parent_leases_for_test(
        world: &mut World,
        owner: &AccountId,
        dataspace_alias: &str,
        dataspace_id: iroha_model_base::topology::DataSpaceId,
        domains: &[&DomainId],
    ) {
        let controller = iroha_data_model::sns::NameControllerV1::account(
            &iroha_data_model::account::AccountAddress::from_account_id(owner)
                .expect("parent lease owner address"),
        );
        let dataspace_selector = iroha_core::sns::selector_for_dataspace_alias(dataspace_alias)
            .expect("dataspace selector");
        let mut dataspace_metadata = iroha_model_base::metadata::Metadata::default();
        dataspace_metadata.insert(
            iroha_core::sns::SNS_DATASPACE_ID_METADATA_KEY
                .parse()
                .expect("dataspace metadata key"),
            iroha_primitives::json::Json::new(dataspace_id.as_u64()),
        );
        let dataspace_record = iroha_data_model::sns::NameRecordV1::new(
            dataspace_selector.clone(),
            owner.clone(),
            vec![controller.clone()],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            dataspace_metadata,
        );
        world.smart_contract_state_mut_for_testing().insert(
            iroha_core::sns::record_storage_key(&dataspace_selector),
            norito::codec::Encode::encode(&dataspace_record),
        );
        for domain in domains {
            let selector =
                iroha_core::sns::selector_for_domain(domain).expect("parent domain selector");
            let record = iroha_data_model::sns::NameRecordV1::new(
                selector.clone(),
                owner.clone(),
                vec![controller.clone()],
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                iroha_model_base::metadata::Metadata::default(),
            );
            world.smart_contract_state_mut_for_testing().insert(
                iroha_core::sns::record_storage_key(&selector),
                norito::codec::Encode::encode(&record),
            );
        }
    }
    #[test]
    fn query_projection_archive_decoder_rejects_noncanonical_norito() {
        let archive = QueryProjectionShardArchive::from_index_status(
            iroha_core::query::index_status::QueryIndexStatus::default(),
            1,
            QueryProjectionResourceKind::Accounts,
            0,
            None,
            1,
            b"row".to_vec(),
        );
        let alternate = {
            let flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _guard = norito::core::DecodeFlagsGuard::enter(flags);
            norito::to_bytes(&archive).expect("encode alternate-layout archive")
        };
        assert!(norito::decode_from_bytes::<QueryProjectionShardArchive>(&alternate).is_ok());
        let compressed = zstd::bulk::compress(&alternate, 3).expect("compress archive");
        assert!(decode_query_projection_archive_payload(&compressed).is_err());
    }
}
