// Outermost HTTP request admission for application-API routed reads.
use http_body_util::BodyExt as _;
#[derive(Clone)]
struct AppRoutedReadHttpAdmission {
    reservation: QueryFanoutMemoryReservation,
    decode_plan: ToriiRoutedReadRequestDecodePlan,
}
tokio::task_local! {
    static APP_ROUTED_READ_HTTP_ADMISSION: AppRoutedReadHttpAdmission;
}
#[cfg(feature = "app_api")]
fn current_app_routed_read_fanout_reservation(
    app: &SharedAppState,
) -> Option<QueryFanoutMemoryReservation> {
    APP_ROUTED_READ_HTTP_ADMISSION
        .try_with(|admission| admission.reservation.clone())
        .ok()
        .filter(|reservation| reservation.belongs_to(app))
}
fn current_app_routed_read_decode_plan() -> Option<ToriiRoutedReadRequestDecodePlan> {
    APP_ROUTED_READ_HTTP_ADMISSION
        .try_with(|admission| admission.decode_plan)
        .ok()
}
#[cfg(feature = "app_api")]
fn app_routed_read_http_admission_is_active() -> bool {
    APP_ROUTED_READ_HTTP_ADMISSION.try_with(|_| ()).is_ok()
}
#[derive(Clone, Debug)]
struct AdmittedAppRoutedReadBody {
    bytes: Bytes,
    #[cfg(feature = "app_api")]
    destination_bytes: usize,
}
#[cfg(feature = "app_api")]
fn admitted_app_routed_read_body(request: &Request<Body>) -> Option<Bytes> {
    if !app_routed_read_http_admission_is_active() {
        return None;
    }
    request
        .extensions()
        .get::<AdmittedAppRoutedReadBody>()
        .map(|body| {
            debug_assert!(body.bytes.len() <= body.destination_bytes);
            body.bytes.clone()
        })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppRoutedReadHttpDecoder {
    #[cfg(feature = "app_api")]
    None,
    #[cfg(feature = "app_api")]
    Query(&'static str),
    StringQuery(&'static str),
    #[cfg(feature = "app_api")]
    JsonOrNorito(&'static str),
    #[cfg(feature = "app_api")]
    Json(&'static str),
    #[cfg(feature = "app_api")]
    ExactInternalAssetScope,
}
impl AppRoutedReadHttpDecoder {
    fn body_type_name(self) -> Option<&'static str> {
        match self {
            #[cfg(feature = "app_api")]
            Self::JsonOrNorito(name) | Self::Json(name) => Some(name),
            #[cfg(feature = "app_api")]
            Self::None | Self::Query(_) | Self::ExactInternalAssetScope => None,
            Self::StringQuery(_) => None,
        }
    }
    fn typed_request_name(self) -> Option<&'static str> {
        match self {
            #[cfg(feature = "app_api")]
            Self::Query(name) | Self::JsonOrNorito(name) | Self::Json(name) => Some(name),
            Self::StringQuery(name) => Some(name),
            #[cfg(feature = "app_api")]
            Self::None | Self::ExactInternalAssetScope => None,
        }
    }
    fn preflight_media(self, _headers: &HeaderMap) -> Result<(), Response> {
        match self {
            #[cfg(feature = "app_api")]
            Self::JsonOrNorito(_) => crate::utils::typed_request_content_format(_headers).map(drop),
            #[cfg(feature = "app_api")]
            Self::Json(_) => crate::utils::canonical_json_request_content_type(_headers),
            #[cfg(feature = "app_api")]
            Self::None | Self::Query(_) | Self::ExactInternalAssetScope => Ok(()),
            Self::StringQuery(_) => Ok(()),
        }
    }
}
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "app_api")]
struct AppRoutedReadHttpEndpoint {
    endpoint: ToriiReadEndpointV1,
    route: iroha_torii_shared::route_catalog::RouteDescriptor,
    decoder: AppRoutedReadHttpDecoder,
}
#[cfg(feature = "app_api")]
macro_rules! app_routed_read_endpoint {
    ($endpoint:ident, $route:path, $decoder:expr) => {
        AppRoutedReadHttpEndpoint {
            endpoint: ToriiReadEndpointV1::$endpoint,
            route: $route,
            decoder: $decoder,
        }
    };
}
#[cfg(feature = "app_api")]
const APP_ROUTED_READ_HTTP_ENDPOINTS_V1: [AppRoutedReadHttpEndpoint; 49] = [
    app_routed_read_endpoint!(AccountPermissionsQuery, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_PERMISSIONS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(UaidManifestsQuery, route_catalog::application_api::SPACE_DIRECTORY_UAIDS_BY_UAID_MANIFESTS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(AccountGet, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(ExplorerAccountDetail, route_catalog::application_api::EXPLORER_ACCOUNTS_BY_ACCOUNT_ID_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(AccountAssetsGet, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_ASSETS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(AccountAssetsQuery, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_ASSETS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(AccountPermissionsGet, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_PERMISSIONS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(AccountTransactionsGet, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(AccountTransactionsQuery, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(TransactionsQuery, route_catalog::application_api::TRANSACTIONS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(PipelineTransactionStatusGet, route_catalog::pipeline::TRANSACTION_STATUS, AppRoutedReadHttpDecoder::StringQuery("PipelineStatusQuery")),
    app_routed_read_endpoint!(ProofRecordGet, route_catalog::pipeline::PROOF, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(AccountsList, route_catalog::application_api::ACCOUNTS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(AccountsQuery, route_catalog::application_api::ACCOUNTS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(AccountsPortfolio, route_catalog::application_api::ACCOUNTS_BY_UAID_PORTFOLIO_GET, AppRoutedReadHttpDecoder::Query("AccountsPortfolioQuery")),
    app_routed_read_endpoint!(AssetDefinitionsList, route_catalog::application_api::ASSETS_DEFINITIONS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(AssetDefinitionGet, route_catalog::application_api::ASSETS_DEFINITIONS_BY_ASSET_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(AssetDefinitionsQuery, route_catalog::application_api::ASSETS_DEFINITIONS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(AssetHoldersGet, route_catalog::telemetry::ASSET_HOLDERS, AppRoutedReadHttpDecoder::Query("AssetHolderGetParams")),
    app_routed_read_endpoint!(AssetHoldersQuery, route_catalog::telemetry::ASSET_HOLDERS_QUERY, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(DomainsList, route_catalog::application_api::DOMAINS_GET, AppRoutedReadHttpDecoder::Query("Pagination")),
    app_routed_read_endpoint!(DomainsQuery, route_catalog::application_api::DOMAINS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(NftsList, route_catalog::application_api::NFTS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(NftsQuery, route_catalog::application_api::NFTS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(NexusPublicLaneValidators, route_catalog::application_api::NEXUS_PUBLIC_LANES_BY_LANE_ID_VALIDATORS_GET, AppRoutedReadHttpDecoder::Query("PublicLaneValidatorsQueryParams")),
    app_routed_read_endpoint!(NexusPublicLaneStake, route_catalog::application_api::NEXUS_PUBLIC_LANES_BY_LANE_ID_STAKE_GET, AppRoutedReadHttpDecoder::Query("PublicLaneStakeQueryParams")),
    app_routed_read_endpoint!(NexusPublicLaneRewards, route_catalog::application_api::NEXUS_PUBLIC_LANES_BY_LANE_ID_REWARDS_PENDING_GET, AppRoutedReadHttpDecoder::Query("PublicLaneRewardsQueryParams")),
    app_routed_read_endpoint!(NexusDataspacesAccountSummary, route_catalog::application_api::NEXUS_DATASPACES_ACCOUNTS_BY_LITERAL_SUMMARY_GET, AppRoutedReadHttpDecoder::Query("NexusDataspacesAccountSummaryQueryParams")),
    app_routed_read_endpoint!(SpaceDirectoryBindingsGet, route_catalog::application_api::SPACE_DIRECTORY_UAIDS_BY_UAID_GET, AppRoutedReadHttpDecoder::Query("SpaceDirectoryBindingsQuery")),
    app_routed_read_endpoint!(SpaceDirectoryManifestsGet, route_catalog::application_api::SPACE_DIRECTORY_UAIDS_BY_UAID_MANIFESTS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(RwasList, route_catalog::application_api::RWAS_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(RwasQuery, route_catalog::application_api::RWAS_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(AliasResolve, route_catalog::aliases::RESOLVE, AppRoutedReadHttpDecoder::Json("AliasResolveRequestDto")),
    app_routed_read_endpoint!(AliasResolveIndex, route_catalog::aliases::RESOLVE_INDEX, AppRoutedReadHttpDecoder::Json("AliasResolveIndexRequestDto")),
    app_routed_read_endpoint!(AliasLookupByAccount, route_catalog::aliases::BY_ACCOUNT, AppRoutedReadHttpDecoder::Json("AliasLookupByAccountRequestDto")),
    app_routed_read_endpoint!(ExplorerAssetDefinitionDetail, route_catalog::application_api::EXPLORER_ASSET_DEFINITIONS_BY_DEFINITION_ID_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(ExplorerAssetDefinitionEconometrics, route_catalog::application_api::EXPLORER_ASSET_DEFINITIONS_BY_DEFINITION_ID_ECONOMETRICS_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(ExplorerAssetDefinitionSnapshot, route_catalog::application_api::EXPLORER_ASSET_DEFINITIONS_BY_DEFINITION_ID_SNAPSHOT_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(ContractAliasResolve, route_catalog::contracts_and_verification_keys::CONTRACTS_ALIASES_RESOLVE_POST, AppRoutedReadHttpDecoder::Json("ContractAliasResolveRequestDto")),
    app_routed_read_endpoint!(ContractStateGet, route_catalog::contracts_and_verification_keys::CONTRACTS_STATE_GET, AppRoutedReadHttpDecoder::Query("ContractStateQuery")),
    app_routed_read_endpoint!(ContractViewPost, route_catalog::contracts_and_verification_keys::CONTRACTS_VIEW_POST, AppRoutedReadHttpDecoder::JsonOrNorito("ContractViewDto")),
    app_routed_read_endpoint!(ContractViewBatchPost, route_catalog::contracts_and_verification_keys::CONTRACTS_VIEW_BATCH_POST, AppRoutedReadHttpDecoder::JsonOrNorito("ContractViewBatchDto")),
    app_routed_read_endpoint!(AccountHistoryQuery, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_HISTORY_QUERY_POST, AppRoutedReadHttpDecoder::Json("ListQuery")),
    app_routed_read_endpoint!(AccountHistoryGet, route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_HISTORY_GET, AppRoutedReadHttpDecoder::Query("ListQuery")),
    app_routed_read_endpoint!(InternalAccountGet, route_catalog::application_api::INTERNAL_ACCOUNTS_BY_ACCOUNT_ID_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(InternalAccountTransactionGet, route_catalog::application_api::INTERNAL_ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_BY_ENTRYPOINT_HASH_GET, AppRoutedReadHttpDecoder::None),
    app_routed_read_endpoint!(InternalAccountAssetGet, route_catalog::application_api::INTERNAL_ACCOUNTS_BY_ACCOUNT_ID_ASSETS_BY_ASSET_DEFINITION_ID_GET, AppRoutedReadHttpDecoder::ExactInternalAssetScope),
    app_routed_read_endpoint!(ContractDeploymentState, route_catalog::contracts_and_verification_keys::CONTRACTS_DEPLOYMENT_STATE_POST, AppRoutedReadHttpDecoder::Json("ContractDeploymentStateRequestDto")),
    app_routed_read_endpoint!(AccountOnboardingCurrentState, route_catalog::application_api::ACCOUNTS_ONBOARDING_CURRENT_STATE_POST, AppRoutedReadHttpDecoder::Json("AccountOnboardingCurrentStateRequestV1")),
];
/// Closed local collections share the HTTP owner without inventing wire endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "app_api")]
enum AppLocalCollectionRead {
    ContractActivity,
    ContractEvents,
    RepoAgreements,
    SubscriptionPlans,
    Subscriptions,
    ExplorerAccounts,
    ExplorerDomains,
    ExplorerAssetDefinitions,
    ExplorerAssets,
    ExplorerNfts,
    ExplorerRwas,
    ExplorerBlocks,
    ExplorerTransactions,
    ExplorerLatestTransactions,
    ExplorerInstructions,
    ExplorerLatestInstructions,
    ExplorerBlockDetail,
    ExplorerTransactionDetail,
    ExplorerInstructionDetail,
    ExplorerInstructionContractView,
    ExplorerHealth,
    ExplorerDomainDetail,
    ExplorerAssetDetail,
    ExplorerNftDetail,
    ExplorerRwaDetail,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppReadHttpIdentity {
    #[cfg(feature = "app_api")]
    Routed(ToriiReadEndpointV1),
    #[cfg(feature = "app_api")]
    LocalCollection(AppLocalCollectionRead),
    Sccp(SccpHttpRead),
}
#[derive(Clone, Copy, Debug)]
struct AppReadHttpRoute {
    endpoint: AppReadHttpIdentity,
    route: iroha_torii_shared::route_catalog::RouteDescriptor,
    decoder: AppRoutedReadHttpDecoder,
}
#[cfg(feature = "app_api")]
const APP_LOCAL_COLLECTION_HTTP_ROUTES_V1: [AppReadHttpRoute; 41] = [
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ContractActivity),
        route: route_catalog::application_api::CONTRACTS_ACTIVITY_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ContractActivity),
        route: route_catalog::application_api::CONTRACTS_ACTIVITY_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ContractEvents),
        route: route_catalog::application_api::CONTRACTS_EVENTS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ContractEvents),
        route: route_catalog::application_api::CONTRACTS_EVENTS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::RepoAgreements),
        route: route_catalog::application_api::REPO_AGREEMENTS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::RepoAgreements),
        route: route_catalog::application_api::REPO_AGREEMENTS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::SubscriptionPlans),
        route: route_catalog::application_api::SUBSCRIPTIONS_PLANS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::SubscriptionPlans),
        route: route_catalog::application_api::SUBSCRIPTIONS_PLANS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::Subscriptions),
        route: route_catalog::application_api::SUBSCRIPTIONS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::Subscriptions),
        route: route_catalog::application_api::SUBSCRIPTIONS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerAccounts),
        route: route_catalog::application_api::EXPLORER_ACCOUNTS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerAccounts),
        route: route_catalog::application_api::EXPLORER_ACCOUNTS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerDomains),
        route: route_catalog::application_api::EXPLORER_DOMAINS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerDomains),
        route: route_catalog::application_api::EXPLORER_DOMAINS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerAssetDefinitions,
        ),
        route: route_catalog::application_api::EXPLORER_ASSET_DEFINITIONS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerAssetDefinitions,
        ),
        route: route_catalog::application_api::EXPLORER_ASSET_DEFINITIONS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerAssets),
        route: route_catalog::application_api::EXPLORER_ASSETS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerAssets),
        route: route_catalog::application_api::EXPLORER_ASSETS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerNfts),
        route: route_catalog::application_api::EXPLORER_NFTS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerNfts),
        route: route_catalog::application_api::EXPLORER_NFTS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerRwas),
        route: route_catalog::application_api::EXPLORER_RWAS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerRwas),
        route: route_catalog::application_api::EXPLORER_RWAS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerBlocks),
        route: route_catalog::application_api::EXPLORER_BLOCKS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerBlocks),
        route: route_catalog::application_api::EXPLORER_BLOCKS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerTransactions,
        ),
        route: route_catalog::application_api::EXPLORER_TRANSACTIONS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerTransactions,
        ),
        route: route_catalog::application_api::EXPLORER_TRANSACTIONS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerLatestTransactions,
        ),
        route: route_catalog::application_api::EXPLORER_TRANSACTIONS_LATEST_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerLatestTransactions,
        ),
        route: route_catalog::application_api::EXPLORER_TRANSACTIONS_LATEST_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerInstructions,
        ),
        route: route_catalog::application_api::EXPLORER_INSTRUCTIONS_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerInstructions,
        ),
        route: route_catalog::application_api::EXPLORER_INSTRUCTIONS_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerLatestInstructions,
        ),
        route: route_catalog::application_api::EXPLORER_INSTRUCTIONS_LATEST_GET,
        decoder: AppRoutedReadHttpDecoder::Query("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerLatestInstructions,
        ),
        route: route_catalog::application_api::EXPLORER_INSTRUCTIONS_LATEST_QUERY_POST,
        decoder: AppRoutedReadHttpDecoder::Json("ListQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerBlockDetail),
        route: route_catalog::application_api::EXPLORER_BLOCKS_BY_IDENTIFIER_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerTransactionDetail,
        ),
        route: route_catalog::application_api::EXPLORER_TRANSACTIONS_BY_HASH_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerInstructionDetail,
        ),
        route: route_catalog::application_api::EXPLORER_INSTRUCTIONS_BY_HASH_BY_INDEX_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerInstructionContractView,
        ),
        route:
            route_catalog::application_api::EXPLORER_INSTRUCTIONS_BY_HASH_BY_INDEX_CONTRACT_VIEW_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerHealth),
        route: route_catalog::application_api::EXPLORER_HEALTH_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(
            AppLocalCollectionRead::ExplorerDomainDetail,
        ),
        route: route_catalog::application_api::EXPLORER_DOMAINS_BY_DOMAIN_ID_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerAssetDetail),
        route: route_catalog::application_api::EXPLORER_ASSETS_BY_ASSET_ID_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerNftDetail),
        route: route_catalog::application_api::EXPLORER_NFTS_BY_NFT_ID_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::LocalCollection(AppLocalCollectionRead::ExplorerRwaDetail),
        route: route_catalog::application_api::EXPLORER_RWAS_BY_RWA_ID_GET,
        decoder: AppRoutedReadHttpDecoder::None,
    },
];
/// Closed SCCP selectors reuse the exact bodyless request admission and decoder corridor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SccpHttpRead {
    History,
    MessageProof,
    ControlProof,
}
const SCCP_HTTP_READ_ROUTES_V1: [AppReadHttpRoute; 3] = [
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::Sccp(SccpHttpRead::History),
        route: route_catalog::sccp::HISTORY,
        decoder: AppRoutedReadHttpDecoder::StringQuery("HistoryQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::Sccp(SccpHttpRead::MessageProof),
        route: route_catalog::sccp::MESSAGE_PROOF,
        decoder: AppRoutedReadHttpDecoder::StringQuery("ProofQuery"),
    },
    AppReadHttpRoute {
        endpoint: AppReadHttpIdentity::Sccp(SccpHttpRead::ControlProof),
        route: route_catalog::sccp::CONTROL_PROOF,
        decoder: AppRoutedReadHttpDecoder::StringQuery("ProofQuery"),
    },
];
fn app_routed_read_http_endpoint(route_id: &str) -> Option<AppReadHttpRoute> {
    if let Some(entry) = SCCP_HTTP_READ_ROUTES_V1
        .iter()
        .copied()
        .find(|entry| entry.route.stable_route_id() == route_id)
    {
        return Some(entry);
    }
    #[cfg(feature = "app_api")]
    {
        return APP_ROUTED_READ_HTTP_ENDPOINTS_V1
            .iter()
            .map(|entry| AppReadHttpRoute {
                endpoint: AppReadHttpIdentity::Routed(entry.endpoint),
                route: entry.route,
                decoder: entry.decoder,
            })
            .chain(APP_LOCAL_COLLECTION_HTTP_ROUTES_V1.iter().copied())
            .find(|entry| entry.route.stable_route_id() == route_id);
    }
    #[cfg(not(feature = "app_api"))]
    None
}
async fn enforce_app_routed_read_http_admission(
    State(app): State<SharedAppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(endpoint) = request
        .extensions()
        .get::<MatchedRouteMetadata>()
        .and_then(|metadata| app_routed_read_http_endpoint(metadata.stable_route_id()))
    else {
        return next.run(request).await;
    };
    if let Err(response) = endpoint.decoder.preflight_media(request.headers()) {
        return response;
    }
    let decode_plan = match ToriiRoutedReadMemoryBudget::new(
        app.query_fanout_working_set_bytes,
        app.torii_proxy_max_response_bytes,
    )
    .and_then(|budget| budget.request_decode_plan_for_path(endpoint.route.path()))
    {
        Ok(plan) => plan,
        Err(response) => return response,
    };
    // Hyper has already retained the complete request target. Charge its URI
    // representation once, including an absolute-form scheme/authority, fixed
    // route literals, dynamic percent-encoded path segments, and query bytes.
    // Axum's path percent decoder can only shrink this representation before
    // bounded typed/canonical parsing starts.
    let target_bytes = app_routed_read_raw_target_bytes(request.uri());
    if let Err(response) = decode_plan.admit_raw_input(target_bytes) {
        return map_app_routed_read_request_response(response);
    }
    let accepts_body = endpoint.decoder.body_type_name().is_some();
    let body_limit = if accepts_body {
        decode_plan
            .raw_input_limit_bytes
            .saturating_sub(target_bytes)
    } else {
        0
    };
    let _preflight_declared_body_bytes = match if accepts_body {
        preflight_app_routed_read_content_length(request.headers(), body_limit)
    } else {
        preflight_bodyless_app_routed_read(request.headers())
    } {
        Ok(declared) => declared,
        Err(response) => return response,
    };
    // Axum has already installed its decoded URL-parameter Arcs before an
    // endpoint middleware runs. That pre-route allocation is covered by the
    // listener's bounded HTTP-head envelope. Reject an over-P target before a
    // fanout permit can overlap it; for an accepted target, the decoded values
    // only shrink and share the outer P phase with the exact body destination.
    let reservation = match acquire_app_routed_read_http_memory(&app, accepts_body).await {
        Ok(reservation) => reservation,
        Err(response) => return response,
    };
    // From admission onward, every decoder uses the geometry owned by this
    // permit. The earlier configuration-derived plan only preflights framing
    // before acquisition; it cannot authorize a larger retained decode graph.
    let decode_plan = match ToriiRoutedReadMemoryBudget::from_envelope(
        match reservation.admitted_envelope(&app) {
            Ok(envelope) => envelope,
            Err(response) => {
                return hold_query_fanout_memory_in_response_body(response, reservation);
            }
        },
        app.torii_proxy_max_response_bytes,
    )
    .request_decode_plan_for_path(endpoint.route.path())
    {
        Ok(plan) => plan,
        Err(response) => return hold_query_fanout_memory_in_response_body(response, reservation),
    };
    if let Err(response) = decode_plan.admit_raw_input(target_bytes) {
        return hold_query_fanout_memory_in_response_body(
            map_app_routed_read_request_response(response),
            reservation,
        );
    }
    let body_limit = if accepts_body {
        decode_plan
            .raw_input_limit_bytes
            .saturating_sub(target_bytes)
    } else {
        0
    };
    let declared_body_bytes = match if accepts_body {
        preflight_app_routed_read_content_length(request.headers(), body_limit)
    } else {
        preflight_bodyless_app_routed_read(request.headers())
    } {
        Ok(declared) => declared,
        Err(response) => return hold_query_fanout_memory_in_response_body(response, reservation),
    };
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        app.app_api_routed_read_body_read_timeout,
        collect_app_routed_read_body(body, body_limit, declared_body_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(response)) => {
            return hold_query_fanout_memory_in_response_body(response, reservation);
        }
        Err(_) => {
            let response = torii_proxy_error_response(
                StatusCode::REQUEST_TIMEOUT,
                "request_body_timeout",
                "The admitted application routed-read body did not complete before its absolute deadline.",
            );
            return hold_query_fanout_memory_in_response_body(response, reservation);
        }
    };
    let mut request = Request::from_parts(parts, Body::from(body.bytes.clone()));
    if accepts_body {
        request.extensions_mut().insert(body);
    }
    let admission = AppRoutedReadHttpAdmission {
        reservation: reservation.clone(),
        decode_plan,
    };
    let response = APP_ROUTED_READ_HTTP_ADMISSION
        .scope(admission, next.run(request))
        .await;
    let _inventory_identity = (endpoint.endpoint, endpoint.decoder.typed_request_name());
    hold_app_routed_read_reservation_if_needed(response, reservation)
}
fn app_routed_read_raw_target_bytes(uri: &axum::http::Uri) -> usize {
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().len(), |target| target.as_str().len());
    let mut total = Some(path_and_query);
    if let Some(scheme) = uri.scheme_str() {
        total = total
            .and_then(|bytes| bytes.checked_add(scheme.len()))
            .and_then(|bytes| bytes.checked_add(1)); // `:`
    }
    if let Some(authority) = uri.authority() {
        let prefix = if uri.scheme().is_some() { 2 } else { 0 }; // `//`
        total = total
            .and_then(|bytes| bytes.checked_add(prefix))
            .and_then(|bytes| bytes.checked_add(authority.as_str().len()));
    }
    // A parsed in-memory URI cannot realistically overflow this sum. Mapping
    // overflow above every valid admission limit keeps the boundary fail-closed.
    total.unwrap_or(usize::MAX)
}
fn hold_app_routed_read_reservation_if_needed(
    response: Response,
    reservation: QueryFanoutMemoryReservation,
) -> Response {
    if response
        .extensions()
        .get::<QueryFanoutMemoryReservation>()
        .is_some()
    {
        response
    } else {
        hold_query_fanout_memory_in_response_body(response, reservation)
    }
}
fn preflight_app_routed_read_content_length(
    headers: &HeaderMap,
    body_limit: usize,
) -> Result<Option<usize>, Response> {
    if headers.contains_key(axum::http::header::CONTENT_LENGTH)
        && headers.contains_key(axum::http::header::TRANSFER_ENCODING)
    {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_body_invalid",
            "Content-Length and Transfer-Encoding cannot both frame one request body.",
        ));
    }
    let mut values = headers.get_all(axum::http::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_body_invalid",
            "The request contains multiple Content-Length values.",
        ));
    }
    let encoded = value.as_bytes();
    if encoded.is_empty()
        || !encoded.iter().all(u8::is_ascii_digit)
        || (encoded.len() > 1 && encoded[0] == b'0')
    {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_body_invalid",
            "The request Content-Length is not a canonical unsigned decimal.",
        ));
    }
    let declared = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            app_routed_read_request_capacity_response(
                "declared body bytes",
                body_limit.saturating_add(1),
                body_limit,
            )
        })?;
    if declared > body_limit {
        return Err(app_routed_read_request_capacity_response(
            "declared body bytes",
            declared,
            body_limit,
        ));
    }
    Ok(Some(declared))
}
fn preflight_bodyless_app_routed_read(headers: &HeaderMap) -> Result<Option<usize>, Response> {
    if headers.contains_key(axum::http::header::TRANSFER_ENCODING) {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_body_invalid",
            "This application routed-read endpoint does not accept a framed request body.",
        ));
    }
    preflight_app_routed_read_content_length(headers, 0)
}
async fn collect_app_routed_read_body(
    body: Body,
    limit: usize,
    declared_bytes: Option<usize>,
) -> Result<AdmittedAppRoutedReadBody, Response> {
    // A missing Content-Length owns the entire P-sized destination while the
    // stream is collected. A non-empty exact owner moves into the request
    // extension and replacement body; a zero-length owner is dropped only
    // after EOF and replaced by the canonical static empty `Bytes` value.
    let destination_bytes = declared_bytes.unwrap_or(limit);
    let storage = torii_allocate_exact_bytes(destination_bytes).map_err(|error| match error {
        norito::json::BoundedJsonError::AllocationFailed => torii_proxy_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "route_unavailable",
            "The admitted application request destination could not be allocated.",
        ),
        _ => app_routed_read_request_capacity_response(
            "raw body bytes",
            destination_bytes,
            destination_bytes,
        ),
    })?;
    let mut owner = ExactAppRoutedReadBody { storage, len: 0 };
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| app_routed_read_body_error_response())?;
        let data = frame.into_data().map_err(|_| {
            torii_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "request_body_invalid",
                "Application routed-read request trailers are not accepted.",
            )
        })?;
        if data.is_empty() {
            continue;
        }
        let next = owner.len.checked_add(data.len()).ok_or_else(|| {
            app_routed_read_request_capacity_response(
                "raw body bytes",
                limit.saturating_add(1),
                limit,
            )
        })?;
        if next > destination_bytes {
            return Err(app_routed_read_request_capacity_response(
                "raw body bytes",
                next,
                destination_bytes,
            ));
        }
        for (slot, byte) in owner.storage[owner.len..next].iter_mut().zip(data.iter()) {
            slot.write(*byte);
        }
        owner.len = next;
    }
    if let Some(declared_bytes) = declared_bytes
        && owner.len != declared_bytes
    {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_REQUEST,
            "request_body_invalid",
            format!(
                "The request body length differs from Content-Length (actual {}, declared {declared_bytes}).",
                owner.len
            ),
        ));
    }
    let bytes = if owner.len == 0 {
        Bytes::new()
    } else {
        Bytes::from_owner(owner)
    };
    Ok(AdmittedAppRoutedReadBody {
        bytes,
        #[cfg(feature = "app_api")]
        destination_bytes,
    })
}
fn app_routed_read_body_error_response() -> Response {
    torii_proxy_error_response(
        StatusCode::BAD_REQUEST,
        "request_body_invalid",
        "The application routed-read request body stream failed.",
    )
}
struct ExactAppRoutedReadBody {
    storage: Box<[std::mem::MaybeUninit<u8>]>,
    len: usize,
}
impl AsRef<[u8]> for ExactAppRoutedReadBody {
    #[allow(unsafe_code)]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the collector initializes exactly `len` leading bytes before
        // constructing the owner-backed `Bytes`, and never mutates it later.
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.len) }
    }
}
#[cfg(all(test, feature = "app_api"))]
include!("tests/lib_routed_reads/app_routed_read_http_admission.rs");

#[cfg(test)]
#[path = "tests/lib_routed_reads/sccp_http_admission.rs"]
mod sccp_http_admission_tests;
