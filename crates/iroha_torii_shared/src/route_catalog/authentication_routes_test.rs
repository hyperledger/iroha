#[derive(Clone, Copy, Default)]
struct RoutePolicyExpectation {
    stable_route_id: Option<&'static str>,
    method: Option<HttpMethod>,
    path: Option<&'static str>,
    surface: Option<ApiSurface>,
    effect: Option<RouteEffect>,
    admission: Option<AdmissionPolicy>,
    authentication: Option<AuthenticationPolicy>,
    projections: Option<RouteProjections>,
    openapi: Option<bool>,
    sdk: Option<bool>,
    mcp: Option<bool>,
    cors_options: Option<bool>,
    path_normalization: Option<PathNormalization>,
    no_trailing_slash: bool,
    app_api_enabled: Option<bool>,
    cataloged: Option<bool>,
}

const EMPTY_POLICY: RoutePolicyExpectation = RoutePolicyExpectation {
    stable_route_id: None,
    method: None,
    path: None,
    surface: None,
    effect: None,
    admission: None,
    authentication: None,
    projections: None,
    openapi: None,
    sdk: None,
    mcp: None,
    cors_options: None,
    path_normalization: None,
    no_trailing_slash: false,
    app_api_enabled: None,
    cataloged: None,
};
const ACCOUNT_AUTHENTICATED: RoutePolicyExpectation = RoutePolicyExpectation {
    admission: Some(AdmissionPolicy::AuthenticatedAccount),
    authentication: Some(AuthenticationPolicy::CanonicalAccountSignature),
    ..EMPTY_POLICY
};
const ACCOUNT_EXPENSIVE: RoutePolicyExpectation = RoutePolicyExpectation {
    effect: Some(RouteEffect::ExpensiveCompute),
    ..ACCOUNT_AUTHENTICATED
};
const DATASPACE_READ: RoutePolicyExpectation = RoutePolicyExpectation {
    effect: Some(RouteEffect::ReadOnly),
    admission: Some(AdmissionPolicy::DataspaceVisible),
    authentication: Some(AuthenticationPolicy::OptionalCanonicalAccountSignature),
    ..EMPTY_POLICY
};
const ACCOUNT_MUTATION: RoutePolicyExpectation = RoutePolicyExpectation {
    effect: Some(RouteEffect::Mutation),
    ..ACCOUNT_AUTHENTICATED
};
const OPERATOR_READ: RoutePolicyExpectation = RoutePolicyExpectation {
    method: Some(HttpMethod::Get),
    surface: Some(ApiSurface::Operator),
    effect: Some(RouteEffect::ReadOnly),
    admission: Some(AdmissionPolicy::Operator),
    authentication: Some(AuthenticationPolicy::OperatorSignature),
    ..EMPTY_POLICY
};
const PUBLIC_READ: RoutePolicyExpectation = RoutePolicyExpectation {
    method: Some(HttpMethod::Get),
    effect: Some(RouteEffect::ReadOnly),
    admission: Some(AdmissionPolicy::Public),
    authentication: Some(AuthenticationPolicy::ToriiDefault),
    ..EMPTY_POLICY
};

macro_rules! assert_expected_route_value {
    ($route:ident, $expected:ident, $field:ident) => {
        if let Some(value) = $expected.$field {
            assert_eq!(
                $route.$field(),
                value,
                concat!("{} ", stringify!($field), " mismatch"),
                $route.stable_route_id()
            );
        }
    };
}

fn assert_expected_route_flag(
    route: RouteDescriptor,
    label: &str,
    actual: bool,
    expected: Option<bool>,
) {
    if let Some(expected) = expected {
        assert!(
            actual == expected,
            "{} {label} mismatch",
            route.stable_route_id()
        );
    }
}

fn assert_route_policy(route: RouteDescriptor, expected: RoutePolicyExpectation) {
    assert_expected_route_value!(route, expected, stable_route_id);
    assert_expected_route_value!(route, expected, method);
    assert_expected_route_value!(route, expected, path);
    assert_expected_route_value!(route, expected, surface);
    assert_expected_route_value!(route, expected, effect);
    assert_expected_route_value!(route, expected, admission);
    assert_expected_route_value!(route, expected, authentication);
    assert_expected_route_value!(route, expected, projections);
    assert_expected_route_value!(route, expected, path_normalization);
    assert_expected_route_flag(
        route,
        "OpenAPI projection",
        route.projections().openapi(),
        expected.openapi,
    );
    assert_expected_route_flag(
        route,
        "SDK projection",
        route.projections().sdk(),
        expected.sdk,
    );
    assert_expected_route_flag(
        route,
        "MCP projection",
        route.projections().mcp(),
        expected.mcp,
    );
    assert_expected_route_flag(
        route,
        "CORS OPTIONS",
        route.cors_options(),
        expected.cors_options,
    );
    if expected.no_trailing_slash {
        assert!(
            !route.path().ends_with('/'),
            "{} must not expose a redirectable trailing-slash alias",
            route.stable_route_id()
        );
    }
    assert_expected_route_flag(
        route,
        "app_api feature gate",
        route
            .feature_gate()
            .is_enabled(EnabledFeatures::new(&["app_api"])),
        expected.app_api_enabled,
    );
    assert_expected_route_flag(
        route,
        "catalog membership",
        CATALOGED_ROUTES.contains(&route),
        expected.cataloged,
    );
}

fn assert_route_policies(
    routes: impl IntoIterator<Item = RouteDescriptor>,
    expected: RoutePolicyExpectation,
) {
    for route in routes {
        assert_route_policy(route, expected);
    }
}

macro_rules! named_route_policy_test {
    ($name:ident, $body:block) => {
        #[test]
        fn $name() {
            $body
        }
    };
}

named_route_policy_test!(
    collection_queries_preserve_authentication_and_proofs_remain_expensive,
    {
        assert_route_policies(
            [
                application_api::DOMAINS_QUERY_POST,
                application_api::ACCOUNTS_QUERY_POST,
                application_api::TRANSACTIONS_QUERY_POST,
                application_api::ASSETS_DEFINITIONS_QUERY_POST,
                application_api::NFTS_QUERY_POST,
                application_api::RWAS_QUERY_POST,
                application_api::ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_QUERY_POST,
                application_api::ACCOUNTS_BY_ACCOUNT_ID_ASSETS_QUERY_POST,
                telemetry::ASSET_HOLDERS_QUERY,
            ],
            DATASPACE_READ,
        );
        assert_route_policies(
            [application_api::REPO_AGREEMENTS_QUERY_POST],
            RoutePolicyExpectation {
                effect: Some(RouteEffect::ReadOnly),
                ..ACCOUNT_AUTHENTICATED
            },
        );
        assert_route_policy(
            application_api::PROOFS_QUERY_POST,
            RoutePolicyExpectation {
                effect: Some(RouteEffect::ExpensiveCompute),
                admission: Some(AdmissionPolicy::AuthenticatedAccount),
                authentication: Some(AuthenticationPolicy::CanonicalSignedBody),
                ..RoutePolicyExpectation::default()
            },
        );
    }
);

named_route_policy_test!(local_sorafs_governance_state_is_operator_signed, {
    assert_route_policies(
        [
            sorafs::GOVERNANCE_DAG_DASHBOARD,
            sorafs::GOVERNANCE_DAG_HEAD,
            sorafs::GOVERNANCE_DAG_BLOCK,
            sorafs::GOVERNANCE_DAG_NODE,
            sorafs::GOVERNANCE_DAG_PUBLISH_INDEX,
            sorafs::GOVERNANCE_DAG_PUBLISH_DIGEST,
            sorafs::GOVERNANCE_DAG_PUBLISH_KIND,
            sorafs::GOVERNANCE_DAG_CAR_QUEUE,
            sorafs::GOVERNANCE_DAG_CAR_QUEUE_DIGEST,
            sorafs::GOVERNANCE_DAG_CAR_QUEUE_KIND,
            sorafs::GOVERNANCE_DAG_CAR_QUEUE_ARCHIVE,
            sorafs::GOVERNANCE_DAG_RUNTIME,
            sorafs::GOVERNANCE_DAG_RUNTIME_HEAD,
            sorafs::GOVERNANCE_DAG_RUNTIME_BLOCK,
            sorafs::GOVERNANCE_DAG_RUNTIME_NODE,
            sorafs::GOVERNANCE_DAG_RUNTIME_DIGEST,
            sorafs::GOVERNANCE_DAG_RUNTIME_KIND,
        ],
        RoutePolicyExpectation {
            projections: Some(RouteProjections::NONE),
            ..OPERATOR_READ
        },
    );
});

named_route_policy_test!(
    node_local_core_and_pipeline_reads_require_exact_operator_signatures,
    {
        assert_route_policies(
            [
                core::PEERS,
                core::TIME_STATUS,
                pipeline::PREFLIGHT,
                pipeline::POLICY,
                pipeline::PROOF_RETENTION,
                pipeline::RECOVERY,
            ],
            RoutePolicyExpectation {
                openapi: Some(true),
                sdk: Some(true),
                mcp: Some(false),
                cors_options: Some(false),
                ..OPERATOR_READ
            },
        );
    }
);

named_route_policy_test!(
    sorafs_inventory_and_storage_reads_declare_fail_closed_admission,
    {
        assert_route_policies(
            [sorafs::ALIASES, sorafs::REPLICATION],
            RoutePolicyExpectation {
                method: Some(HttpMethod::Get),
                surface: Some(ApiSurface::Public),
                projections: Some(RouteProjections::OPENAPI_AND_SDK),
                ..ACCOUNT_EXPENSIVE
            },
        );
        assert_route_policy(
            sorafs::STORAGE_STATE,
            RoutePolicyExpectation {
                projections: Some(RouteProjections::NONE),
                ..OPERATOR_READ
            },
        );
        assert_route_policies(
            [sorafs::STORAGE_CAR, sorafs::STORAGE_CHUNK],
            RoutePolicyExpectation {
                method: Some(HttpMethod::Get),
                effect: Some(RouteEffect::ReadOnly),
                admission: Some(AdmissionPolicy::AuthenticatedProtocolPrincipal),
                authentication: Some(AuthenticationPolicy::ProtocolHandshake),
                projections: Some(RouteProjections::OPENAPI_AND_SDK),
                ..RoutePolicyExpectation::default()
            },
        );
    }
);

named_route_policy_test!(
    soracloud_commands_require_exact_account_authentication_and_honest_effects,
    {
        let commands = application_api::ROUTES
            .iter()
            .filter(|route| {
                route.method() == HttpMethod::Post
                    && route
                        .stable_route_id()
                        .starts_with("application.soracloud_")
            })
            .collect::<Vec<_>>();
        // Pin the current command identities and effects; a new POST must be reviewed explicitly.
        // The retired model-host commands and HF deploy are replaced by shared-lease join.
        let expected = std::collections::BTreeMap::from([
            (
                "application.soracloud_agent_autonomy_allow_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_deploy_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_lease_renew_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_message_ack_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_message_send_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_policy_revoke_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_restart_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_wallet_approve_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_agent_wallet_spend_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_apps_deploy_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_apps_upgrade_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_ciphertext_query_post",
                RouteEffect::ReadOnly,
            ),
            (
                "application.soracloud_decrypt_request_post",
                RouteEffect::Mutation,
            ),
            ("application.soracloud_deploy_post", RouteEffect::Mutation),
            (
                "application.soracloud_fhe_job_run_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_health_access_request_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_hf_lease_leave_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_hf_lease_renew_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_hf_shared_lease_join_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_model_artifact_register_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_model_upload_register_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_model_weight_promote_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_model_weight_register_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_model_weight_rollback_post",
                RouteEffect::Mutation,
            ),
            ("application.soracloud_rollback_post", RouteEffect::Mutation),
            ("application.soracloud_rollout_post", RouteEffect::Mutation),
            (
                "application.soracloud_service_config_delete_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_service_config_set_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_service_secret_delete_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_service_secret_set_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_state_mutate_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_training_job_checkpoint_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_training_job_retry_post",
                RouteEffect::Mutation,
            ),
            (
                "application.soracloud_training_job_start_post",
                RouteEffect::Mutation,
            ),
            ("application.soracloud_upgrade_post", RouteEffect::Mutation),
        ]);
        let actual = commands
            .iter()
            .map(|route| (route.stable_route_id(), route.effect()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            actual, expected,
            "every current SoraCloud POST must have an explicit reviewed effect"
        );
        assert_route_policies(commands.iter().map(|route| **route), ACCOUNT_AUTHENTICATED);
    }
);

named_route_policy_test!(
    soracloud_sensitive_reads_require_exact_account_authentication,
    {
        let protected = [
            application_api::SORACLOUD_STATUS_GET,
            application_api::SORACLOUD_APPS_STATUS_GET,
            application_api::SORACLOUD_APPS_BY_APP_NAME_STATUS_GET,
            application_api::SORACLOUD_SERVICE_CONFIG_STATUS_GET,
            application_api::SORACLOUD_SERVICE_SECRET_STATUS_GET,
            application_api::SORACLOUD_HEALTH_COMPLIANCE_REPORT_GET,
            application_api::SORACLOUD_TRAINING_JOB_STATUS_GET,
            application_api::SORACLOUD_MODEL_WEIGHT_STATUS_GET,
            application_api::SORACLOUD_MODEL_ARTIFACT_STATUS_GET,
            application_api::SORACLOUD_MODEL_UPLOAD_STATUS_GET,
            application_api::SORACLOUD_HF_SHARED_LEASE_STATUS_GET,
            application_api::SORACLOUD_AGENT_STATUS_GET,
            application_api::SORACLOUD_AGENT_MAILBOX_STATUS_GET,
            application_api::SORACLOUD_AGENT_AUTONOMY_STATUS_GET,
        ];
        assert_eq!(
            protected.len(),
            14,
            "every sensitive Soracloud GET must be classified"
        );
        assert_route_policies(
            protected,
            RoutePolicyExpectation {
                method: Some(HttpMethod::Get),
                effect: Some(RouteEffect::ReadOnly),
                ..ACCOUNT_AUTHENTICATED
            },
        );
    }
);

named_route_policy_test!(
    soracloud_public_reads_are_bounded_single_object_discovery,
    {
        assert_route_policies(
        [
            application_api::SORACLOUD_SERVICES_BY_SERVICE_NAME_PUBLIC_DISCOVERY_GET,
            application_api::SORACLOUD_SERVICES_BY_SERVICE_NAME_REVISIONS_BY_SERVICE_VERSION_PUBLIC_DISCOVERY_GET,
        ],
        PUBLIC_READ,
    );
    }
);

named_route_policy_test!(
    subscription_commands_require_exact_account_authentication_and_mutation_admission,
    {
        assert_route_policies(
            [
                application_api::SUBSCRIPTIONS_PLANS_POST,
                application_api::SUBSCRIPTIONS_POST,
                application_api::SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_PAUSE_POST,
                application_api::SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_RESUME_POST,
                application_api::SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_CANCEL_POST,
                application_api::SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_KEEP_POST,
                application_api::SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_USAGE_POST,
                application_api::SUBSCRIPTIONS_BY_SUBSCRIPTION_ID_CHARGE_NOW_POST,
            ],
            ACCOUNT_MUTATION,
        );
    }
);

named_route_policy_test!(
    application_drafts_and_cryptographic_services_require_exact_account_authentication,
    {
        assert_route_policies(
            [
                application_api::SPACE_DIRECTORY_MANIFESTS_POST,
                application_api::SPACE_DIRECTORY_MANIFESTS_REVOKE_POST,
                application_api::RAM_LFE_PROGRAMS_BY_PROGRAM_ID_EXECUTE_POST,
                application_api::RAM_LFE_RECEIPTS_VERIFY_POST,
                application_api::ACCOUNTS_BY_ACCOUNT_ID_IDENTIFIERS_CLAIM_RECEIPT_POST,
                application_api::IDENTIFIERS_RESOLVE_POST,
            ],
            RoutePolicyExpectation {
                method: Some(HttpMethod::Post),
                ..ACCOUNT_EXPENSIVE
            },
        );
    }
);

named_route_policy_test!(webhook_registry_is_operator_signed_and_effects_are_exact, {
    assert_route_policy(
        application_api::WEBHOOKS_GET,
        RoutePolicyExpectation {
            effect: Some(RouteEffect::ReadOnly),
            admission: Some(AdmissionPolicy::Operator),
            authentication: Some(AuthenticationPolicy::OperatorSignature),
            ..RoutePolicyExpectation::default()
        },
    );
    assert_route_policies(
        [
            application_api::WEBHOOKS_POST,
            application_api::WEBHOOKS_BY_ID_DELETE,
        ],
        RoutePolicyExpectation {
            effect: Some(RouteEffect::Mutation),
            admission: Some(AdmissionPolicy::Operator),
            authentication: Some(AuthenticationPolicy::OperatorSignature),
            ..RoutePolicyExpectation::default()
        },
    );
});

named_route_policy_test!(
    zk_attachment_tenant_routes_are_account_authenticated_before_storage_access,
    {
        assert_route_policies(
            [
                runtime_governance::ZK_ATTACHMENTS_GET,
                runtime_governance::ZK_ATTACHMENTS_POST,
                runtime_governance::ZK_ATTACHMENT_GET,
                runtime_governance::ZK_ATTACHMENT_DELETE,
                runtime_governance::ZK_ATTACHMENTS_COUNT,
            ],
            ACCOUNT_AUTHENTICATED,
        );
        assert_route_policies(
            [
                runtime_governance::ZK_ATTACHMENTS_POST,
                runtime_governance::ZK_ATTACHMENT_DELETE,
            ],
            RoutePolicyExpectation {
                effect: Some(RouteEffect::Mutation),
                ..RoutePolicyExpectation::default()
            },
        );
    }
);

named_route_policy_test!(zk_compute_routes_require_exact_account_authentication, {
    assert_route_policies([runtime_governance::ZK_VERIFY_BATCH], ACCOUNT_EXPENSIVE);
});

named_route_policy_test!(account_and_node_bootstrap_capabilities_are_public, {
    assert_route_policies(
        [
            application_api::ACCOUNTS_CAPABILITIES_GET,
            application_api::ACCOUNTS_FAUCET_POLICY_GET,
        ],
        RoutePolicyExpectation {
            projections: Some(RouteProjections::OPENAPI_AND_SDK),
            openapi: Some(true),
            sdk: Some(true),
            app_api_enabled: Some(true),
            cataloged: Some(true),
            ..PUBLIC_READ
        },
    );
    assert_route_policies([runtime_governance::NODE_CAPABILITIES], PUBLIC_READ);
});

named_route_policy_test!(
    state_backed_runtime_and_governance_routes_require_exact_account_authentication,
    {
        assert_route_policies(
            [
                runtime_governance::ZK_ROOTS,
                runtime_governance::ZK_MERKLE_PATH,
                runtime_governance::ZK_VOTE_TALLY,
                runtime_governance::RUNTIME_ABI_ACTIVE,
                runtime_governance::RUNTIME_METRICS,
                runtime_governance::PRIVACY_CAPABILITIES,
                runtime_governance::NODE_PROJECTION_CHECKPOINT,
                runtime_governance::MINISTRY_AGENDA_DRAFT,
                runtime_governance::MINISTRY_AGENDA_GET,
                runtime_governance::GOV_PROPOSE_DEPLOY,
                runtime_governance::GOV_PROPOSE_SCCP,
                runtime_governance::GOV_CAPABILITIES,
                runtime_governance::GOV_CITIZEN_DRAFT,
                runtime_governance::GOV_PARLIAMENT_ATTEMPT_DRAFT,
                runtime_governance::GOV_PARLIAMENT_ATTEMPT_READ,
                runtime_governance::GOV_PARLIAMENT_ATTEMPT_PLAN,
                runtime_governance::GOV_PARLIAMENT_TRANSITION_DRAFT,
                runtime_governance::VALIDATION_FEE_CURRENT_POLICY_PROOF,
                runtime_governance::VALIDATION_FEE_PROPOSALS,
                runtime_governance::VALIDATION_FEE_PROPOSAL_DETAIL,
                runtime_governance::VALIDATION_FEE_PROPOSAL_DRAFT,
                runtime_governance::GOV_PROPOSAL_GET,
                runtime_governance::GOV_LOCKS_GET,
                runtime_governance::GOV_REFERENDUM_GET,
                runtime_governance::GOV_TALLY_GET,
                runtime_governance::GOV_PROTECTED_GET,
                runtime_governance::GOV_UNLOCK_STATS,
                runtime_governance::GOV_CONTRACT_GET,
                runtime_governance::GOV_CITIZENS_COUNT,
                runtime_governance::GOV_CITIZEN_STATUS,
            ],
            RoutePolicyExpectation {
                path_normalization: Some(PathNormalization::Strict),
                no_trailing_slash: true,
                ..ACCOUNT_AUTHENTICATED
            },
        );
        assert_route_policies(
            [
                runtime_governance::ZK_ROOTS,
                runtime_governance::ZK_MERKLE_PATH,
                runtime_governance::RUNTIME_METRICS,
                runtime_governance::VALIDATION_FEE_CURRENT_POLICY_PROOF,
                runtime_governance::VALIDATION_FEE_PROPOSAL_DETAIL,
                runtime_governance::GOV_LOCKS_GET,
                runtime_governance::GOV_TALLY_GET,
            ],
            RoutePolicyExpectation {
                effect: Some(RouteEffect::ExpensiveCompute),
                ..RoutePolicyExpectation::default()
            },
        );
        assert_route_policies(
            [runtime_governance::RUNTIME_ABI_HASH],
            RoutePolicyExpectation {
                effect: Some(RouteEffect::ReadOnly),
                admission: Some(AdmissionPolicy::Public),
                authentication: Some(AuthenticationPolicy::ToriiDefault),
                ..RoutePolicyExpectation::default()
            },
        );
    }
);

named_route_policy_test!(
    moderation_dead_letter_routes_are_account_signed_operator_role_posts,
    {
        let routes = [
            (
                contracts_and_verification_keys::SORAFS_MODERATION_DEAD_LETTERS_PREPARE_POST,
                "contracts.sorafs_moderation_dead_letters_prepare_post",
                "/v1/sorafs/moderation/dead-letters/prepare",
            ),
            (
                contracts_and_verification_keys::SORAFS_MODERATION_DEAD_LETTERS_APPLY_POST,
                "contracts.sorafs_moderation_dead_letters_apply_post",
                "/v1/sorafs/moderation/dead-letters/apply",
            ),
        ];
        for (route, stable_route_id, path) in routes {
            assert_route_policy(
                route,
                RoutePolicyExpectation {
                    stable_route_id: Some(stable_route_id),
                    method: Some(HttpMethod::Post),
                    path: Some(path),
                    surface: Some(ApiSurface::Public),
                    authentication: Some(AuthenticationPolicy::CanonicalAccountSignature),
                    projections: Some(RouteProjections::OPENAPI_AND_SDK),
                    cors_options: Some(true),
                    app_api_enabled: Some(true),
                    cataloged: Some(true),
                    ..RoutePolicyExpectation::default()
                },
            );
        }
        assert_eq!(validate_catalog(&routes.map(|(route, _, _)| route)), Ok(()));
    }
);
