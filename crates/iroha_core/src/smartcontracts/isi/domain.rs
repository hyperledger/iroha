//! This module contains [`Domain`] structure and related implementations and trait implementations.
use super::super::isi::prelude::*;
use eyre::Result;
use iroha_data_model::{account::rekey::AccountRekeyRecord, prelude::*, query::error::FindError};
use iroha_telemetry::metrics;
/// ISI module contains all instructions related to domains:
/// - creating/changing assets
/// - registering/unregistering accounts
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use super::*;
    use crate::{
        alias::{
            authority_can_manage_account_alias, authority_can_manage_account_alias_scope,
            authority_can_manage_asset_definition_alias,
        },
        state::{
            WorldReadOnly as _, account_label_is_pii, public_lane_stake_share_matches_key,
            public_lane_validator_record_matches_key,
        },
    };
    use iroha_crypto::{Algorithm, PublicKey};
    use iroha_data_model::{
        IntoKeyValue,
        account::{
            AccountController,
            curve::{CurveId, CurveRegistryError},
        },
        alias_setup::{AccountAliasRoleV1, AliasAccountIntentV1},
        asset::definition::{
            validate_asset_alias_against_names, validate_asset_description, validate_asset_name,
        },
        asset::{
            ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, ASSET_TRANSFER_CONTROL_METADATA_KEY,
            AssetBalancePolicy,
        },
        isi::error::{InstructionExecutionError, InvalidParameterError, RepetitionError},
        nexus::DataSpaceCatalog,
    };
    use iroha_logger::prelude::*;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use iroha_model_base::topology::DataSpaceId;
    use std::{collections::BTreeSet, str::FromStr};
    /// Alias grace window after lease expiry (369 hours).
    const ASSET_ALIAS_GRACE_MS: u64 = 369u64 * 60 * 60 * 1_000;
    include!("domain/asset_alias_scope.rs");
    /// Exact private-root home admission and original refusal controls.
    #[cfg(test)]
    mod private_root_home_tests {
        include!("domain/private_root_home_tests.rs");
    }
}
/// Implementations for domain queries.
pub mod query {
    use super::*;
    use crate::smartcontracts::isi::query::json_predicate::{
        parse_domain_predicate_value, predicate_matches_with_aliases,
    };
    use crate::{
        smartcontracts::{ValidQuery, ValidSingularQuery},
        state::{StateReadOnly, WorldReadOnly},
    };
    use iroha_data_model::{
        domain::Domain,
        query::{
            dsl::{CompoundPredicate, EvaluatePredicate},
            error::QueryExecutionFail,
            json::{PredicateJson, predicate_json_candidate_plan_for_execution},
        },
    };
    use iroha_model_base::domain::DomainId;
    use norito::json::Value;
    use std::collections::BTreeSet;
    #[derive(Debug, Default)]
    struct DomainPredicateView {
        ids: BTreeSet<DomainId>,
        owners: BTreeSet<AccountId>,
    }
    impl DomainPredicateView {
        fn from_predicate(predicate: &CompoundPredicate<Domain>) -> Self {
            let mut view = Self::default();
            let Some(raw) = predicate.json_payload() else {
                return view;
            };
            let Some(predicate) = predicate_json_candidate_plan_for_execution(raw) else {
                return view;
            };
            for condition in predicate.equals {
                view.push_field_value(&condition.field, &condition.value);
            }
            for membership in predicate.r#in {
                for value in membership.values {
                    view.push_field_value(&membership.field, &value);
                }
            }
            view
        }
        fn push_field_value(&mut self, field: &str, value: &Value) {
            let Value::String(raw) = value else {
                return;
            };
            match field {
                "id" | "domain" | "domain_id" => {
                    if let Some(domain_id) = parse_domain_predicate_value(raw) {
                        self.ids.insert(domain_id);
                    }
                }
                "owner" | "owned_by" | "account" | "account_id" => {
                    if let Ok(account_id) = AccountId::parse_encoded(raw) {
                        self.owners.insert(account_id.subject_id());
                    }
                }
                _ => {}
            }
        }
        fn plan(&self) -> DomainQueryPlan {
            let mut ids = self.ids.iter().cloned().collect::<Vec<_>>();
            ids.sort();
            let mut owners = self.owners.iter().cloned().collect::<Vec<_>>();
            owners.sort();
            if !ids.is_empty() {
                return DomainQueryPlan::Ids(ids);
            }
            if !owners.is_empty() {
                return DomainQueryPlan::Owners(owners);
            }
            DomainQueryPlan::Full
        }
    }
    #[derive(Debug)]
    enum DomainQueryPlan {
        Ids(Vec<DomainId>),
        Owners(Vec<AccountId>),
        Full,
    }
    fn domain_alias_values(domain: &Domain, field: &str) -> Vec<String> {
        match field {
            "id" | "domain" | "domain_id" => {
                let canonical = domain.id().to_string();
                let shorthand = domain.id().name().to_string();
                if canonical == shorthand {
                    vec![canonical]
                } else {
                    vec![canonical, shorthand]
                }
            }
            "owner" | "owned_by" | "account" | "account_id" => {
                vec![domain.owned_by().to_string()]
            }
            _ => Vec::new(),
        }
    }
    fn predicate_matches_domain(predicate: &PredicateJson, domain: &Domain) -> bool {
        predicate_matches_with_aliases(predicate, domain, domain_alias_values)
    }
    impl ValidSingularQuery for FindDomainById {
        #[metrics(+"find_domain_by_id")]
        fn execute(
            &self,
            state_ro: &impl StateReadOnly,
        ) -> std::result::Result<Domain, QueryExecutionFail> {
            let domain = state_ro
                .world()
                .domain(self.domain_id())
                .map_err(QueryExecutionFail::from)?;
            crate::smartcontracts::isi::query::own_singular_query_value(domain)
        }
    }
    impl ValidQuery for FindDomains {
        #[metrics(+"find_domains")]
        fn execute(
            self,
            filter: CompoundPredicate<Domain>,
            state_ro: &impl StateReadOnly,
        ) -> std::result::Result<impl Iterator<Item = Domain>, QueryExecutionFail> {
            let world = state_ro.world();
            let predicate_view = DomainPredicateView::from_predicate(&filter);
            let predicate_json = filter
                .json_payload()
                .and_then(predicate_json_candidate_plan_for_execution);
            let iter: Box<dyn Iterator<Item = Domain> + '_> = match predicate_view.plan() {
                DomainQueryPlan::Ids(ids) => Box::new(
                    ids.into_iter()
                        .filter_map(move |domain_id| world.domain(&domain_id).ok().cloned()),
                ),
                DomainQueryPlan::Owners(owners) => {
                    Box::new(owners.into_iter().flat_map(move |owner| {
                        world
                            .domains_by_owner()
                            .get(&owner)
                            .cloned()
                            .into_iter()
                            .flatten()
                            .filter_map(move |domain_id| world.domain(&domain_id).ok().cloned())
                    }))
                }
                DomainQueryPlan::Full => Box::new(world.domains_iter().cloned()),
            };
            Ok(iter.filter(move |domain| {
                if let Some(predicate) = predicate_json.as_ref() {
                    predicate_matches_domain(predicate, domain)
                } else {
                    filter.applies(domain)
                }
            }))
        }
    }
    impl ValidQuery for FindDomainsByAccountId {
        #[metrics(+"find_domains_by_account_id")]
        fn execute(
            self,
            filter: CompoundPredicate<Domain>,
            state_ro: &impl StateReadOnly,
        ) -> std::result::Result<impl Iterator<Item = Domain>, QueryExecutionFail> {
            let account_id = self.account_id().clone();
            state_ro.world().account(&account_id)?;
            Ok(state_ro
                .world()
                .domains_owned_by_iter(&account_id)
                .filter(move |domain| filter.applies(domain))
                .cloned())
        }
    }
}
#[cfg(test)]
mod tests {
    include!("domain_restricted_asset_definition_tests.rs");
    use super::isi::upsert_account_rekey_record;
    use super::*;
    use crate::{
        kura::Kura,
        nexus::space_directory::{SpaceDirectoryManifestRecord, SpaceDirectoryManifestSet},
        prelude::World,
        query::store::LiveQueryStore,
        smartcontracts::{ValidQuery, ValidSingularQuery},
        state::{
            GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum, State,
            WorldReadOnly,
        },
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        IntoKeyValue,
        account::{
            Account, AccountAddress, NewAccount, OpaqueAccountId,
            controller::{MultisigMember, MultisigPolicy},
            rekey::{AccountAlias, AccountRekeyRecord, AccountRekeyTransitionProvenance},
        },
        alias_setup::{
            AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
            AliasIntentV1, AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedAccountAliasV1,
        },
        asset::{
            ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, ASSET_TRANSFER_CONTROL_METADATA_KEY, Asset,
            AssetBalancePolicy, AssetDefinition, AssetDefinitionAlias, AssetDefinitionId, AssetId,
            AssetIssuerUsagePolicyV1, AssetTransferControlRecord, AssetTransferControlStoreV1,
            Mintable, NewAssetDefinition, ResolvedAssetDefinitionAliasV1,
        },
        block::BlockHeader,
        events::data::space_directory::{
            SpaceDirectoryEvent, SpaceDirectoryManifestActivated, SpaceDirectoryManifestRevoked,
        },
        isi::{
            SetAssetTransferBlacklist,
            alias_setup::{CompareAndSetPrimaryAccountAlias, EnsureAlias, RebindAccountAlias},
            error::{InstructionExecutionError, InvalidParameterError, RepetitionError},
        },
        nexus::{
            AssetPermissionManifest, DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig,
            LaneVisibility, ManifestVersion, UniversalAccountId,
        },
        nft::{Nft, NftId},
        permission::Permission,
        prelude::Domain,
        privacy::{
            PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyPoolIdV1, PrivacyPoolNamespaceV1,
            PrivacyProtocolIdV1,
        },
        role::{Role, RoleId},
        smart_contract::ContractAddress,
        sns::{NameControllerV1, NameRecordV1},
    };
    use iroha_executor_data_model::permission::account::{
        AccountAliasPermissionScope, CanManageAccountAlias, CanRegisterAccount,
    };
    use iroha_executor_data_model::permission::asset_definition::{
        AssetDefinitionAliasPermissionScope, CanManageAssetDefinitionAlias,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_model_base::peer::PeerId;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_primitives::{
        json::Json,
        numeric::{NumericSpec, Quantity},
    };
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use nonzero_ext::nonzero;
    use std::sync::Arc;
    fn test_state() -> State {
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        State::new_for_testing(World::default(), kura, query)
    }
    #[test]
    fn issuer_usage_policy_metadata_requires_definition_owner_in_native_execution() {
        let domain_id = DomainId::try_new("retail", "universal").expect("domain id");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "kina".parse().expect("asset name"),
        );
        let world = World::with_assets(
            [Domain::new(domain_id).build(&ALICE_ID)],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
            ],
            [AssetDefinition::numeric(
                definition_id.clone(),
                "Digital Kina".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .build(&ALICE_ID)],
            [],
            [],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        // Height two is deliberately outside the initial-genesis permission exception.
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let policy_key: Name = ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
            .parse()
            .expect("issuer policy key");
        let policy_value = Json::new(AssetIssuerUsagePolicyV1::default());
        let unauthorized_set = SetKeyValue::asset_definition(
            definition_id.clone(),
            policy_key.clone(),
            policy_value.clone(),
        )
        .execute(&BOB_ID, &mut tx)
        .expect_err("metadata delegate cannot change issuer policy");
        assert!(
            unauthorized_set
                .to_string()
                .contains("issuer usage policy requires asset-definition owner")
        );
        assert!(
            tx.world
                .asset_definition(&definition_id)
                .expect("definition")
                .metadata()
                .get(&policy_key)
                .is_none()
        );
        SetKeyValue::asset_definition(definition_id.clone(), policy_key.clone(), policy_value)
            .execute(&ALICE_ID, &mut tx)
            .expect("issuer owner can set policy");
        let unauthorized_remove =
            RemoveKeyValue::asset_definition(definition_id.clone(), policy_key.clone())
                .execute(&BOB_ID, &mut tx)
                .expect_err("metadata delegate cannot remove issuer policy");
        assert!(
            unauthorized_remove
                .to_string()
                .contains("issuer usage policy requires asset-definition owner")
        );
        assert!(
            tx.world
                .asset_definition(&definition_id)
                .expect("definition")
                .metadata()
                .get(&policy_key)
                .is_some()
        );
        RemoveKeyValue::asset_definition(definition_id.clone(), policy_key)
            .execute(&ALICE_ID, &mut tx)
            .expect("issuer owner can remove policy");
        let ordinary_key: Name = "ordinary_note".parse().expect("ordinary key");
        SetKeyValue::asset_definition(definition_id, ordinary_key, Json::new(true))
            .execute(&BOB_ID, &mut tx)
            .expect("native issuer restriction does not cover ordinary metadata");
    }
    fn fixture_keypair(seed: u8, algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], algorithm)
            .expect("fixture seed must derive a valid keypair")
    }
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("domain ISI fixture key generation should succeed")
    }

    #[test]
    fn account_registration_rejects_reserved_native_metadata() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("transfer", "controls").expect("domain id"),
            "rose".parse().expect("asset name"),
        );
        let mut record = AssetTransferControlRecord::new(asset_definition_id);
        record.blacklisted = true;
        let duplicate_store = AssetTransferControlStoreV1 {
            controls: vec![record.clone(), record],
        };
        let reserved_values = [
            (
                ASSET_TRANSFER_CONTROL_METADATA_KEY,
                Json::new(duplicate_store),
            ),
            (
                iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY,
                Json::new(7_u64),
            ),
        ];
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        for (key, value) in reserved_values {
            let account_id = AccountId::new(checked_keypair().public_key().clone());
            let mut metadata = Metadata::default();
            metadata.insert(key.parse().expect("reserved metadata key"), value);
            let error =
                Register::account(NewAccount::new(account_id.clone()).with_metadata(metadata))
                    .execute(&authority, &mut transaction)
                    .expect_err("public registration must not seed reserved native metadata");
            assert!(
                error.to_string().contains("reserved for native state"),
                "unexpected registration rejection: {error}"
            );
            assert!(
                transaction.world.account(&account_id).is_err(),
                "rejected account registration must not mutate world state"
            );
        }
    }

    #[test]
    fn account_unregistration_requires_dedicated_transfer_control_clear() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id = DomainId::try_new("transfer", "controls").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "rose".parse().expect("asset name"),
        );
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "rose".to_owned(),
            AssetBalancePolicy::Global,
            None,
        ))
        .execute(&authority, &mut transaction)
        .expect("register controlled asset definition");
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut transaction)
            .expect("register controlled account");
        let mut record = AssetTransferControlRecord::new(asset_definition_id.clone());
        record.blacklisted = true;
        record.updated_at_ms = Some(1);
        let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
            .parse()
            .expect("asset transfer-control metadata key");
        transaction
            .world
            .account_mut(&account_id)
            .expect("registered account")
            .insert(
                metadata_key.clone(),
                Json::new(AssetTransferControlStoreV1 {
                    controls: vec![record],
                }),
            );

        let error = Unregister::account(account_id.clone())
            .execute(&authority, &mut transaction)
            .expect_err("native transfer-control history must survive generic account removal");
        assert!(
            error.to_string().contains("dedicated instructions"),
            "unexpected account-removal rejection: {error}"
        );
        assert!(transaction.world.account(&account_id).is_ok());

        let asset_error = Unregister::asset_definition(asset_definition_id.clone())
            .execute(&authority, &mut transaction)
            .expect_err("asset definition must remain while native controls reference it");
        assert!(
            asset_error.to_string().contains("dedicated instructions"),
            "unexpected asset-definition removal rejection: {asset_error}"
        );

        SetAssetTransferBlacklist::new(account_id.clone(), asset_definition_id.clone(), false)
            .execute(&authority, &mut transaction)
            .expect("dedicated instruction clears the last native transfer control");
        assert!(
            transaction
                .world
                .account(&account_id)
                .expect("account remains until explicit removal")
                .metadata()
                .get(&metadata_key)
                .is_none()
        );
        Unregister::asset_definition(asset_definition_id)
            .execute(&authority, &mut transaction)
            .expect("asset definition can be removed after dedicated control clearance");
        Unregister::account(account_id.clone())
            .execute(&authority, &mut transaction)
            .expect("account can be removed after dedicated control clearance");
        assert!(transaction.world.account(&account_id).is_err());
    }
    fn checked_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .expect("domain ISI fixture key generation for requested algorithm should succeed")
    }
    fn install_orchard_pool_dependency_guard(
        state_transaction: &mut crate::state::StateTransaction<'_, '_>,
        asset_definition_id: AssetDefinitionId,
        reserve_account: AccountId,
    ) -> crate::privacy_state::PrivacyCommitmentKeyV1 {
        let namespace = PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([0xD1; 32]),
            }),
        );
        let bootstrap = iroha_data_model::privacy::PrivacyOrchardPoolBootstrapV1::new(
            PrivacyPoolIdV1::new([0xD1; 32]),
            asset_definition_id,
            iroha_data_model::asset::AssetBalanceScope::Global,
            reserve_account,
        )
        .expect("canonical Orchard dependency-guard bootstrap");
        let pool_state = crate::privacy_state::PrivacyOrchardPoolStateV1::bootstrap(bootstrap)
            .expect("canonical Orchard dependency-guard state");
        let reserve_asset_id = iroha_data_model::asset::AssetId::with_scope(
            pool_state.asset_definition_id().clone(),
            pool_state.reserve_account().clone(),
            pool_state.public_balance_scope(),
        );
        let owner = crate::privacy_state::PrivacyPublicReserveOwnerV1::Orchard {
            namespace,
            bootstrap_digest: pool_state.bootstrap_digest(),
        };
        let custody_key = crate::privacy_state::PrivacyCommitmentKeyV1::public_reserve_custody(
            owner.protocol_id(),
            &reserve_asset_id,
        )
        .expect("canonical Orchard reserve key");
        let custody_record =
            crate::privacy_state::PrivacyStateItemRecordV1::public_reserve_custody(
                reserve_asset_id,
                owner,
            )
            .expect("canonical Orchard reserve record");
        let key = crate::privacy_state::PrivacyCommitmentKeyV1::orchard_pool_state(namespace)
            .expect("canonical Orchard dependency-guard key");
        let record = crate::privacy_state::PrivacyStateItemRecordV1::orchard_pool_state(pool_state)
            .expect("canonical Orchard dependency-guard record");
        assert!(
            state_transaction
                .world
                .privacy_commitments
                .insert(key, record)
                .is_none()
        );
        assert!(
            state_transaction
                .world
                .privacy_commitments
                .insert(custody_key, custody_record)
                .is_none()
        );
        key
    }
    fn instruction_error_contains(error: &InstructionExecutionError, expected: &str) -> bool {
        match error {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) => message.contains(expected),
            InstructionExecutionError::InvariantViolation(message) => message.contains(expected),
            _ => false,
        }
    }
    #[test]
    fn checked_keypair_helpers_preserve_requested_algorithms() {
        assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        for algorithm in [Algorithm::Secp256k1, Algorithm::BlsNormal] {
            assert_eq!(
                checked_keypair_with_algorithm(algorithm).algorithm(),
                algorithm
            );
        }
    }
    #[test]
    fn generic_domain_metadata_isis_cannot_mutate_native_kaigi_state() {
        use iroha_data_model::kaigi::{
            KaigiRelayAllowlist, kaigi_metadata_key, kaigi_relay_allowlist_key,
            kaigi_relay_feedback_key, kaigi_relay_metadata_key,
        };

        let authority = (*ALICE_ID).clone();
        let domain_id = DomainId::try_new("kaigi", "universal").expect("domain id");
        let mut state = test_state();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let call_name: Name = "protected".parse().expect("call name");
        let reserved_keys = [
            kaigi_metadata_key(&call_name).expect("call metadata key"),
            kaigi_relay_metadata_key(&authority).expect("relay metadata key"),
            kaigi_relay_feedback_key(&authority).expect("relay feedback key"),
        ];

        for key in reserved_keys {
            let error = SetKeyValue::domain(
                domain_id.clone(),
                key.clone(),
                Json::new("forged Kaigi state"),
            )
            .execute(&authority, &mut transaction)
            .expect_err("generic metadata set must reject native Kaigi keys");
            assert!(instruction_error_contains(
                &error,
                "reserved for native Kaigi state"
            ));
            assert!(
                transaction
                    .world
                    .domain(&domain_id)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_none(),
                "rejected set must not mutate {key}"
            );

            transaction
                .world
                .domain_mut(&domain_id)
                .expect("domain")
                .metadata_mut()
                .insert(key.clone(), Json::new("pre-existing native state"));
            let error = RemoveKeyValue::domain(domain_id.clone(), key.clone())
                .execute(&authority, &mut transaction)
                .expect_err("generic metadata remove must reject native Kaigi keys");
            assert!(instruction_error_contains(
                &error,
                "reserved for native Kaigi state"
            ));
            assert!(
                transaction
                    .world
                    .domain(&domain_id)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_some(),
                "rejected removal must preserve {key}"
            );
        }

        let allowlist_key = kaigi_relay_allowlist_key().expect("allowlist metadata key");
        let mut allowlist = KaigiRelayAllowlist::default();
        for _ in 0..iroha_data_model::kaigi::KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1 {
            let (relay_id, _) = iroha_test_samples::gen_account_in("allowlist");
            allowlist.allowed_relays.insert(relay_id);
        }
        let exact_limit = Json::try_new(allowlist.clone()).expect("exact-limit allowlist JSON");
        SetKeyValue::domain(
            domain_id.clone(),
            allowlist_key.clone(),
            exact_limit.clone(),
        )
        .execute(&authority, &mut transaction)
        .expect("domain governance must accept the exact relay allowlist limit");
        let (extra_relay, _) = iroha_test_samples::gen_account_in("allowlist");
        allowlist.allowed_relays.insert(extra_relay);
        let over_limit = Json::try_new(allowlist).expect("over-limit allowlist JSON");
        let error = SetKeyValue::domain(domain_id.clone(), allowlist_key.clone(), over_limit)
            .execute(&authority, &mut transaction)
            .expect_err("domain governance must reject an over-limit relay allowlist");
        assert!(instruction_error_contains(&error, "500-entry limit"));
        assert_eq!(
            transaction
                .world
                .domain(&domain_id)
                .expect("domain")
                .metadata()
                .get(&allowlist_key),
            Some(&exact_limit),
            "a rejected allowlist replacement must preserve the previous value"
        );
        RemoveKeyValue::domain(domain_id, allowlist_key)
            .execute(&authority, &mut transaction)
            .expect("domain governance must be able to remove the relay allowlist");
    }
    #[test]
    fn unregister_account_rejects_active_kaigi_host_atomically() {
        use iroha_data_model::kaigi::{KaigiId, KaigiRecord, NewKaigi, kaigi_metadata_key};

        let authority = (*ALICE_ID).clone();
        let domain_id = DomainId::try_new("kaigi-host", "universal").expect("domain id");
        let host = AccountId::new(checked_keypair().public_key().clone());
        let call_name: Name = "active-call".parse().expect("call name");
        let call = KaigiId::new(domain_id.clone(), call_name.clone());
        let record = KaigiRecord::from_new(&NewKaigi::with_defaults(call.clone(), host.clone()), 1);
        let key = kaigi_metadata_key(&call_name).expect("Kaigi metadata key");
        let value = Json::try_new(record.clone()).expect("Kaigi record JSON");

        let mut state = test_state();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        seed_account(&mut state, &host, &domain_id);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        crate::smartcontracts::isi::kaigi::store_kaigi_record_for_testing(
            &mut transaction,
            &record,
        )
        .expect("store indexed Kaigi fixture");

        assert!(transaction.world.take_external_events().is_empty());

        let error = Unregister::account(host.clone())
            .execute(&authority, &mut transaction)
            .expect_err("an active Kaigi host must remain registered");

        assert!(instruction_error_contains(
            &error,
            "referenced by active Kaigi"
        ));
        assert!(
            transaction.world.accounts.get(&host).is_some(),
            "rejected account removal must preserve the host"
        );
        assert_eq!(
            transaction
                .world
                .domain(&domain_id)
                .expect("Kaigi domain")
                .metadata()
                .get(&key),
            Some(&value),
            "rejected account removal must preserve the active Kaigi record"
        );
        assert!(
            transaction.world.take_external_events().is_empty(),
            "rejected account removal must not emit events"
        );
    }
    #[test]
    fn stale_alias_purge_preserves_kaigi_rekey_continuity_atomically() {
        use iroha_data_model::{
            account::rekey::AccountAliasDomain,
            kaigi::{KaigiId, KaigiRecord, NewKaigi},
        };

        let authority = (*ALICE_ID).clone();
        let alias_domain = DomainId::try_new("identity", "universal").expect("alias domain");
        let call_domain = DomainId::try_new("calls", "universal").expect("call domain");
        let predecessor = AccountId::new(checked_keypair().public_key().clone());
        let terminal = AccountId::new(checked_keypair().public_key().clone());
        let missing_alias_owner = AccountId::new(checked_keypair().public_key().clone());
        let alias = AccountAlias::new(
            "continuity".parse().expect("alias label"),
            Some(AccountAliasDomain::new(alias_domain.name().clone())),
            DataSpaceId::UNIVERSAL,
        );
        let history = AccountRekeyRecord::new(alias.clone(), predecessor.clone())
            .repoint_for_account_id_rekey(terminal.clone())
            .expect("canonical account-id rekey")
            .reassign_alias_to_account(missing_alias_owner.clone())
            .expect("independent alias reassignment");
        let call_name: Name = "active-call".parse().expect("call name");
        let call = KaigiId::new(call_domain.clone(), call_name.clone());
        let record = KaigiRecord::from_new(&NewKaigi::with_defaults(call, predecessor.clone()), 1);

        let mut state = test_state();
        for domain in [&alias_domain, &call_domain] {
            seed_domain(&mut state, domain, &authority);
        }
        seed_account(&mut state, &authority, &call_domain);
        seed_account(&mut state, &terminal, &alias_domain);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        transaction
            .world
            .insert_account_alias_binding(alias.clone(), missing_alias_owner.clone());
        transaction
            .world
            .replace_account_rekey_record(history.clone());
        crate::smartcontracts::isi::kaigi::store_kaigi_record_for_testing(
            &mut transaction,
            &record,
        )
        .expect("store indexed Kaigi fixture");

        let error = super::isi::purge_stale_account_label_state(&mut transaction, &alias)
            .expect_err("stale cleanup must not erase required Kaigi continuity");
        assert!(instruction_error_contains(
            &error,
            "history is required by native Kaigi state"
        ));
        assert_eq!(
            transaction.world.account_aliases.get(&alias),
            Some(&missing_alias_owner),
            "failed purge must preserve the forward binding"
        );
        assert_eq!(
            transaction.world.account_rekey_records.get(&alias),
            Some(&history),
            "failed purge must preserve the continuity record"
        );
    }
    fn seed_domain(state: &mut State, domain_id: &DomainId, owner: &AccountId) {
        let domain = Domain {
            id: domain_id.clone(),
            logo: None,
            metadata: Metadata::default(),
            owned_by: owner.clone(),
        };
        state.world.domains.insert(domain_id.clone(), domain);
        let mut domains = state
            .world
            .domains_by_owner
            .view()
            .get(owner)
            .cloned()
            .unwrap_or_default();
        domains.insert(domain_id.clone());
        state.world.domains_by_owner.insert(owner.clone(), domains);
    }
    fn seed_account(state: &mut State, account_id: &AccountId, domain_id: &DomainId) {
        let account = Account {
            id: account_id.clone(),
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let _ = domain_id;
        let (account_id, account_value) = account.into_key_value();
        state.world.accounts.insert(account_id, account_value);
    }
    fn test_state_with_authority(authority: &AccountId) -> State {
        let mut state = test_state();
        let domain_id = DomainId::try_new("authority", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, authority);
        seed_account(&mut state, authority, &domain_id);
        state
    }
    #[test]
    fn unregister_account_rejects_governed_orchard_reserve_dependency_atomically() {
        let authority = (*ALICE_ID).clone();
        let mut state = test_state_with_authority(&authority);
        let domain_id =
            DomainId::try_new("orchard_account", "guard").expect("Orchard guard domain");
        seed_domain(&mut state, &domain_id, &authority);
        let reserve_account = AccountId::new(checked_keypair().public_key().clone());
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "coin".parse().expect("asset name"),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::account(NewAccount::new(reserve_account.clone()))
            .execute(&authority, &mut transaction)
            .expect("register Orchard reserve account");
        Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&authority, &mut transaction)
        .expect("register Orchard backing definition");
        let state_key = install_orchard_pool_dependency_guard(
            &mut transaction,
            asset_definition_id,
            reserve_account.clone(),
        );
        let error = Unregister::account(reserve_account.clone())
            .execute(&authority, &mut transaction)
            .expect_err("governed Orchard reserve account must remain registered");
        assert!(
            error
                .to_string()
                .contains("reserve account for governed privacy pool"),
            "{error}"
        );
        assert!(transaction.world.accounts.get(&reserve_account).is_some());
        assert!(
            transaction
                .world
                .privacy_commitments
                .get(&state_key)
                .is_some()
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_governed_orchard_dependency_atomically() {
        let authority = (*ALICE_ID).clone();
        let mut state = test_state_with_authority(&authority);
        let domain_id = DomainId::try_new("orchard_asset", "guard").expect("Orchard guard domain");
        seed_domain(&mut state, &domain_id, &authority);
        let reserve_account = AccountId::new(checked_keypair().public_key().clone());
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "coin".parse().expect("asset name"),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::account(NewAccount::new(reserve_account.clone()))
            .execute(&authority, &mut transaction)
            .expect("register Orchard reserve account");
        Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&authority, &mut transaction)
        .expect("register Orchard backing definition");
        let state_key = install_orchard_pool_dependency_guard(
            &mut transaction,
            asset_definition_id.clone(),
            reserve_account,
        );
        let error = Unregister::asset_definition(asset_definition_id.clone())
            .execute(&authority, &mut transaction)
            .expect_err("governed Orchard backing definition must remain registered");
        assert!(
            error.to_string().contains("backs governed privacy pool"),
            "{error}"
        );
        assert!(
            transaction
                .world
                .asset_definitions
                .get(&asset_definition_id)
                .is_some()
        );
        assert!(
            transaction
                .world
                .privacy_commitments
                .get(&state_key)
                .is_some()
        );
    }
    #[test]
    fn unregister_domain_rejects_governed_orchard_asset_cascade_before_mutation() {
        let authority = (*ALICE_ID).clone();
        let mut state = test_state_with_authority(&authority);
        let domain_id =
            DomainId::try_new("orchard_domain", "universal").expect("Orchard guard domain");
        seed_domain(&mut state, &domain_id, &authority);
        let reserve_account = AccountId::new(checked_keypair().public_key().clone());
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "coin".parse().expect("asset name"),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::account(NewAccount::new(reserve_account.clone()))
            .execute(&authority, &mut transaction)
            .expect("register Orchard reserve account");
        Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ))
        .execute(&authority, &mut transaction)
        .expect("register Orchard backing definition");
        let state_key = install_orchard_pool_dependency_guard(
            &mut transaction,
            asset_definition_id.clone(),
            reserve_account.clone(),
        );
        let error = Unregister::domain(domain_id.clone())
            .execute(&authority, &mut transaction)
            .expect_err("domain cascade must retain governed Orchard backing definition");
        assert!(
            error.to_string().contains("backs governed privacy pool"),
            "{error}"
        );
        assert!(transaction.world.domains.get(&domain_id).is_some());
        assert!(
            transaction
                .world
                .asset_definitions
                .get(&asset_definition_id)
                .is_some()
        );
        assert!(transaction.world.accounts.get(&reserve_account).is_some());
        assert!(
            transaction
                .world
                .privacy_commitments
                .get(&state_key)
                .is_some()
        );
    }
    #[test]
    fn domain_controller_capabilities_check_multisig_members_with_checked_algorithm_access() {
        let allowed = [Algorithm::Ed25519];
        let allowed_curve_ids =
            iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(&allowed);
        let ed25519 = fixture_keypair(0x51, Algorithm::Ed25519);
        let secp256k1 = fixture_keypair(0x52, Algorithm::Secp256k1);
        let allowed_policy = MultisigPolicy::new(
            1,
            vec![MultisigMember::new(ed25519.public_key().clone(), 1).expect("member")],
        )
        .expect("policy");
        super::isi::ensure_controller_capabilities(
            &AccountController::Multisig(allowed_policy),
            &allowed,
            &allowed_curve_ids,
        )
        .expect("Ed25519 multisig member should be accepted");
        let disallowed_policy = MultisigPolicy::new(
            1,
            vec![MultisigMember::new(secp256k1.public_key().clone(), 1).expect("member")],
        )
        .expect("policy");
        let err = super::isi::ensure_controller_capabilities(
            &AccountController::Multisig(disallowed_policy),
            &allowed,
            &allowed_curve_ids,
        )
        .expect_err("Secp256k1 multisig member should be rejected");
        assert!(matches!(
            err,
            InstructionExecutionError::InvariantViolation(_)
        ));
    }
    #[test]
    fn fixture_keypair_uses_checked_seed_derivation() {
        assert_eq!(
            fixture_keypair(0x53, Algorithm::Ed25519).algorithm(),
            Algorithm::Ed25519
        );
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn find_domain_by_id_returns_registered_domain() {
        let mut state = test_state();
        let domain_id = DomainId::try_new("banka", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &ALICE_ID);
        let view = state.view();
        let domain = FindDomainById::new(domain_id.clone())
            .execute(&view)
            .unwrap();
        assert_eq!(domain.id(), &domain_id);
        assert_eq!(domain.owned_by(), &*ALICE_ID);
    }
    #[test]
    fn find_domains_by_account_id_returns_owned_domains_only() {
        use std::collections::BTreeSet;
        let mut state = test_state();
        let owner_domain = DomainId::try_new("owner", "universal").expect("domain id");
        let alice_owned = DomainId::try_new("banka", "universal").expect("domain id");
        let bob_owned = DomainId::try_new("bankb", "universal").expect("domain id");
        let bob_id = AccountId::new(checked_keypair().public_key().clone());
        seed_domain(&mut state, &owner_domain, &ALICE_ID);
        seed_account(&mut state, &ALICE_ID, &owner_domain);
        seed_account(&mut state, &bob_id, &owner_domain);
        seed_domain(&mut state, &alice_owned, &ALICE_ID);
        seed_domain(&mut state, &bob_owned, &bob_id);
        let view = state.view();
        let domains: BTreeSet<_> = FindDomainsByAccountId::new(ALICE_ID.clone())
            .execute(CompoundPredicate::PASS, &view)
            .unwrap()
            .map(|domain| domain.id().clone())
            .collect();
        assert_eq!(domains, BTreeSet::from([owner_domain, alice_owned]));
    }
    #[test]
    fn find_domains_filters_owner_with_owner_index() {
        use std::collections::BTreeSet;
        let mut state = test_state();
        let alice_owned = DomainId::try_new("banka", "universal").expect("domain id");
        let alice_owned_two = DomainId::try_new("cards", "universal").expect("domain id");
        let bob_owned = DomainId::try_new("bankb", "universal").expect("domain id");
        let bob_id = AccountId::new(checked_keypair().public_key().clone());
        seed_domain(&mut state, &alice_owned, &ALICE_ID);
        seed_domain(&mut state, &alice_owned_two, &ALICE_ID);
        seed_domain(&mut state, &bob_owned, &bob_id);
        let view = state.view();
        assert_eq!(
            view.world()
                .domains_owned_by_iter(&ALICE_ID)
                .map(|domain| domain.id().clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([alice_owned.clone(), alice_owned_two.clone()]),
            "fixture should populate the owner index used by the query planner",
        );
        let predicate =
            CompoundPredicate::<Domain>::build(|p| p.equals("owned_by", ALICE_ID.to_string()));
        let domains: BTreeSet<_> = FindDomains
            .execute(predicate, &view)
            .unwrap()
            .map(|domain| domain.id().clone())
            .collect();
        assert_eq!(domains, BTreeSet::from([alice_owned, alice_owned_two]));
    }
    #[test]
    fn domain_owner_index_tracks_insert_transfer_and_remove() {
        let state = test_state();
        let owner = (*ALICE_ID).clone();
        let new_owner = AccountId::new(checked_keypair().public_key().clone());
        let domain_id = DomainId::try_new("indexed", "universal").expect("domain id");
        let domain = Domain {
            id: domain_id.clone(),
            logo: None,
            metadata: Metadata::default(),
            owned_by: owner.clone(),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world.insert_domain_entry(domain_id.clone(), domain);
        let owned_domains = tx
            .world
            .domains_owned_by_iter(&owner)
            .map(|domain| domain.id().clone())
            .collect::<Vec<_>>();
        assert_eq!(owned_domains, vec![domain_id.clone()]);
        {
            let domain = tx.world.domain_mut(&domain_id).expect("domain exists");
            domain.set_owned_by(new_owner.clone());
        }
        tx.world
            .replace_domain_owner_index(&domain_id, &owner, &new_owner);
        assert!(
            tx.world.domains_owned_by_iter(&owner).next().is_none(),
            "owner index should remove transferred domain from previous owner",
        );
        let owned_by_new_owner = tx
            .world
            .domains_owned_by_iter(&new_owner)
            .map(|domain| domain.id().clone())
            .collect::<Vec<_>>();
        assert_eq!(owned_by_new_owner, vec![domain_id.clone()]);
        tx.world.remove_domain_entry(&domain_id);
        assert!(
            tx.world.domains_owned_by_iter(&new_owner).next().is_none(),
            "owner index should remove unregistered domain",
        );
    }
    fn alias_domain(domain: &DomainId) -> AccountAliasDomain {
        AccountAliasDomain::new(domain.name().clone())
    }
    fn alias_in_domain(domain: &DomainId, label: Name) -> AccountAlias {
        AccountAlias::new(label, Some(alias_domain(domain)), DataSpaceId::UNIVERSAL)
    }
    fn alias_in_dataspace_domain(
        domain: &DomainId,
        dataspace: DataSpaceId,
        label: Name,
    ) -> AccountAlias {
        AccountAlias::new_in_dataspace(label, Some(alias_domain(domain)), dataspace)
    }
    fn resolved_account_alias(
        tx: &StateTransaction<'_, '_>,
        alias: &AccountAlias,
    ) -> ResolvedAccountAliasV1 {
        let literal = alias
            .to_literal(&tx.nexus.dataspace_catalog)
            .expect("test alias must resolve through the live catalog");
        ResolvedAccountAliasV1::new(
            literal
                .parse::<AccountAliasName>()
                .expect("test alias literal must be canonical"),
            alias.dataspace,
        )
    }
    fn repair_only_quote_guard() -> AliasQuoteGuardV1 {
        AliasQuoteGuardV1 {
            expected_policy_version: 0,
            expected_payment_asset: AssetDefinitionId::derive_from_components(
                DomainId::try_new("assets", "universal").expect("fixture asset domain"),
                "xor".parse().expect("fixture asset name"),
            ),
            max_amount: Quantity::zero(),
            valid_until_ms: 0,
        }
    }
    /// Test adapter for exercising declarative setup repair against pre-seeded leases.
    struct EnsureTestAccountAliasBinding {
        account: AccountId,
        alias: Option<AccountAlias>,
        lease_expiry_ms: Option<u64>,
    }
    impl EnsureTestAccountAliasBinding {
        fn bind(account: AccountId, alias: AccountAlias, lease_expiry_ms: Option<u64>) -> Self {
            Self {
                account,
                alias: Some(alias),
                lease_expiry_ms,
            }
        }
        fn clear(account: AccountId) -> Self {
            Self {
                account,
                alias: None,
                lease_expiry_ms: None,
            }
        }
    }
    impl Execute for EnsureTestAccountAliasBinding {
        fn execute(
            self,
            authority: &AccountId,
            tx: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            if self.lease_expiry_ms.is_some() {
                return Err(InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(
                        "alias setup never accepts lease expiry; use RenewAliasLease".into(),
                    ),
                )
                .into());
            }
            let alias = self.alias.ok_or_else(|| {
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                    "broad alias clearing was removed; use explicit lifecycle CAS operations"
                        .into(),
                ))
            })?;
            let resolved = resolved_account_alias(tx, &alias);
            EnsureAlias::new(
                AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                    alias: resolved,
                    target_account: self.account,
                    provision: AccountProvisionV1::Existing,
                    role: AccountAliasRoleV1::Additional,
                }),
                AliasLeaseAcquisitionV1::new(1, None),
                repair_only_quote_guard(),
            )
            .execute(authority, tx)
        }
    }
    /// Test adapter for exercising explicit primary-alias compare-and-set semantics.
    struct CasTestPrimaryAccountAlias {
        account: AccountId,
        alias: Option<AccountAlias>,
        lease_expiry_ms: Option<u64>,
    }
    impl CasTestPrimaryAccountAlias {
        fn bind(account: AccountId, alias: AccountAlias, lease_expiry_ms: Option<u64>) -> Self {
            Self {
                account,
                alias: Some(alias),
                lease_expiry_ms,
            }
        }
        fn clear(account: AccountId) -> Self {
            Self {
                account,
                alias: None,
                lease_expiry_ms: None,
            }
        }
    }
    impl Execute for CasTestPrimaryAccountAlias {
        fn execute(
            self,
            authority: &AccountId,
            tx: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            if self.lease_expiry_ms.is_some() {
                return Err(InstructionExecutionError::InvalidParameter(
                    InvalidParameterError::SmartContract(
                        "primary-alias CAS never accepts lease expiry; use RenewAliasLease".into(),
                    ),
                )
                .into());
            }
            let current = tx.world.account(&self.account)?.label().cloned();
            if let Some(alias) = current.as_ref() {
                seed_account_alias_lease_record(tx, &self.account, alias);
            }
            let expected = current
                .as_ref()
                .map(|alias| resolved_account_alias(tx, alias));
            let new_alias = self
                .alias
                .as_ref()
                .map(|alias| resolved_account_alias(tx, alias));
            if let Some(alias) = self.alias
                && current.as_ref() != Some(&alias)
            {
                EnsureTestAccountAliasBinding::bind(self.account.clone(), alias, None)
                    .execute(authority, tx)?;
            }
            CompareAndSetPrimaryAccountAlias::new(self.account, expected, new_alias)
                .execute(authority, tx)
        }
    }
    fn install_retail_dataspace_catalog(
        tx: &mut StateTransaction<'_, '_>,
    ) -> (DataSpaceId, DataSpaceId) {
        let paynet = DataSpaceId::new(12);
        let cbuae = DataSpaceId::new(13);
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: paynet,
                alias: "paynet".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: cbuae,
                alias: "cbuae".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("retail dataspace catalog");
        tx.nexus.dataspace_catalog = catalog.clone();
        tx.world.dataspace_catalog = catalog;
        (paynet, cbuae)
    }
    fn install_dataspace_catalog_with_lane(
        tx: &mut StateTransaction<'_, '_>,
        dataspace: DataSpaceId,
        alias: &str,
        visibility: LaneVisibility,
    ) {
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: dataspace,
                alias: alias.to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("dataspace catalog");
        tx.nexus.dataspace_catalog = catalog.clone();
        tx.world.dataspace_catalog = catalog;
        tx.nexus.lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    dataspace_id: dataspace,
                    alias: alias.to_owned(),
                    visibility,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("lane catalog");
    }
    fn seed_account_alias_manage_permissions(
        tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        alias: &AccountAlias,
    ) {
        if tx.world.account(authority).is_err() {
            let account = Account {
                id: authority.clone(),
                metadata: Metadata::default(),
                label: None,
                uaid: None,
                opaque_ids: Vec::new(),
            };
            let (account_id, account_value) = account.into_key_value();
            tx.world.accounts.insert(account_id, account_value);
        }
        tx.world.add_account_permission(
            authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(alias.dataspace),
            }),
        );
        if let Some(domain_id) = alias
            .domain_id(&tx.nexus.dataspace_catalog)
            .expect("alias domain id")
        {
            tx.world.add_account_permission(
                authority,
                Permission::from(CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Domain(domain_id),
                }),
            );
        }
    }
    fn seed_contract_alias_manage_permissions(
        tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        alias: &ContractAlias,
    ) {
        let (label, domain, dataspace) = super::isi::resolve_contract_alias_components(tx, alias)
            .expect("contract alias components");
        seed_contract_alias_manage_permissions_in_dataspace(
            tx, authority, label, domain, dataspace,
        );
    }
    fn seed_contract_alias_manage_permissions_in_dataspace(
        tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        label: Name,
        domain: Option<AccountAliasDomain>,
        dataspace: DataSpaceId,
    ) {
        seed_account_alias_manage_permissions(
            tx,
            authority,
            &AccountAlias::new_in_dataspace(label, domain, dataspace),
        );
    }
    fn retail_account_aliases(paynet: DataSpaceId, cbuae: DataSpaceId) -> Vec<AccountAlias> {
        let hbl = DomainId::try_new("hbl", "paynet").expect("hbl domain");
        let ubl = DomainId::try_new("ubl", "paynet").expect("ubl domain");
        vec![
            AccountAlias::domainless("retailpaynet".parse::<Name>().expect("label"), paynet),
            alias_in_dataspace_domain(&hbl, paynet, "retailhbl".parse::<Name>().expect("label")),
            alias_in_dataspace_domain(&ubl, paynet, "retailubl".parse::<Name>().expect("label")),
            AccountAlias::domainless("retailcbuae".parse::<Name>().expect("label"), cbuae),
        ]
    }
    fn seed_account_alias_lease(
        tx: &mut StateTransaction<'_, '_>,
        owner: &AccountId,
        alias: &AccountAlias,
    ) {
        seed_account_alias_lease_record(tx, owner, alias);
        if tx.world.account(owner).is_err() {
            let account = Account {
                id: owner.clone(),
                metadata: Metadata::default(),
                label: None,
                uaid: None,
                opaque_ids: Vec::new(),
            };
            let (account_id, account_value) = account.into_key_value();
            tx.world.accounts.insert(account_id, account_value);
        }
        tx.world.add_account_permission(
            owner,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(alias.dataspace),
            }),
        );
        if let Some(domain_id) = alias
            .domain_id(&tx.nexus.dataspace_catalog)
            .expect("domain id")
        {
            tx.world.add_account_permission(
                owner,
                Permission::from(CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Domain(domain_id),
                }),
            );
        }
    }
    fn seed_account_alias_lease_record(
        tx: &mut StateTransaction<'_, '_>,
        owner: &AccountId,
        alias: &AccountAlias,
    ) {
        let dataspace_name = tx
            .nexus
            .dataspace_catalog
            .by_id(alias.dataspace)
            .expect("fixture alias dataspace must be catalogued")
            .alias
            .clone();
        let dataspace_selector =
            crate::sns::selector_for_dataspace_alias(&dataspace_name).expect("dataspace selector");
        let dataspace_key = crate::sns::record_storage_key(&dataspace_selector);
        if tx.world.smart_contract_state.get(&dataspace_key).is_none() {
            let address = AccountAddress::from_account_id(owner).expect("account address");
            let mut metadata = Metadata::default();
            metadata.insert(
                crate::sns::SNS_DATASPACE_ID_METADATA_KEY
                    .parse()
                    .expect("static dataspace metadata key"),
                Json::new(alias.dataspace.as_u64()),
            );
            let record = NameRecordV1::new(
                dataspace_selector,
                owner.clone(),
                vec![NameControllerV1::account(&address)],
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                metadata,
            );
            tx.world
                .smart_contract_state
                .insert(dataspace_key, norito::codec::Encode::encode(&record));
        }
        if let Some(domain_id) = alias
            .domain_id(&tx.nexus.dataspace_catalog)
            .expect("fixture alias domain")
        {
            let domain_owner = tx
                .world
                .domains
                .get(&domain_id)
                .map(|domain| domain.owned_by().clone())
                .unwrap_or_else(|| owner.clone());
            if tx.world.domains.get(&domain_id).is_none() {
                let domain = Domain::new(domain_id.clone()).build(&domain_owner);
                tx.world.insert_domain_entry(domain_id.clone(), domain);
                tx.world.track_domain_owner(&domain_id, &domain_owner);
            }
            let selector =
                crate::sns::selector_for_domain(&domain_id).expect("SNS domain selector");
            let storage_key = crate::sns::record_storage_key(&selector);
            if tx.world.smart_contract_state.get(&storage_key).is_none() {
                let address =
                    AccountAddress::from_account_id(&domain_owner).expect("domain owner address");
                let record = NameRecordV1::new(
                    selector,
                    domain_owner,
                    vec![NameControllerV1::account(&address)],
                    0,
                    0,
                    u64::MAX,
                    u64::MAX,
                    u64::MAX,
                    Metadata::default(),
                );
                tx.world
                    .smart_contract_state
                    .insert(storage_key, norito::codec::Encode::encode(&record));
            }
        }
        let selector = crate::sns::selector_for_account_alias(alias, &tx.nexus.dataspace_catalog)
            .expect("selector");
        let address = AccountAddress::from_account_id(owner).expect("account address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        tx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    }
    fn seed_expired_account_alias_lease_record(
        tx: &mut StateTransaction<'_, '_>,
        owner: &AccountId,
        alias: &AccountAlias,
    ) {
        // Seed the active parent dataspace/domain records first, then replace only
        // the account-alias leaf with an expired lifecycle fixture.
        seed_account_alias_lease_record(tx, owner, alias);
        let selector = crate::sns::selector_for_account_alias(alias, &tx.nexus.dataspace_catalog)
            .expect("selector");
        let address = AccountAddress::from_account_id(owner).expect("account address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            1,
            2,
            3,
            Metadata::default(),
        );
        tx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    }
    fn seed_dataspace_alias_lease(
        tx: &mut StateTransaction<'_, '_>,
        owner: &AccountId,
        alias: &str,
    ) {
        let selector = crate::sns::selector_for_dataspace_alias(alias).expect("selector");
        let address = AccountAddress::from_account_id(owner).expect("account address");
        let record = NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        tx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    }
    fn seed_domainful_alias_manage_permissions(
        tx: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        domain: &DomainId,
    ) {
        tx.world.add_account_permission(
            authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(domain.clone()),
            }),
        );
        tx.world.add_account_permission(
            authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
            }),
        );
    }
    fn seed_manifest_record<F>(
        world: &mut World,
        uaid: UniversalAccountId,
        dataspace: DataSpaceId,
        configure: F,
    ) -> Hash
    where
        F: FnOnce(&mut SpaceDirectoryManifestRecord),
    {
        let manifest = AssetPermissionManifest {
            version: ManifestVersion::default(),
            uaid,
            dataspace,
            issued_ms: 0,
            activation_epoch: 0,
            expiry_epoch: None,
            entries: Vec::new(),
        };
        let mut record = SpaceDirectoryManifestRecord::new(manifest);
        configure(&mut record);
        let manifest_hash = record.manifest_hash;
        let mut set = SpaceDirectoryManifestSet::default();
        set.upsert(record);
        world.space_directory_manifests.insert(uaid, set);
        manifest_hash
    }
    #[test]
    fn account_label_registration_and_cleanup() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let account_label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let new_account = Account::new(account_id.clone()).with_label(Some(account_label.clone()));
        // Execute register with label.
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease_record(&mut tx, &account_id, &account_label);
        Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect("register account with label");
        assert!(
            tx.world.account_rekey_records.get(&account_label).is_some(),
            "rekey record should be inserted"
        );
        assert_eq!(
            tx.world.account_aliases.get(&account_label),
            Some(&account_id),
            "alias index should be inserted"
        );
        // Duplicate label should be rejected.
        let second_keypair = checked_keypair();
        let second_id = AccountId::new(second_keypair.public_key().clone());
        let dup_account = Account::new(second_id.clone()).with_label(Some(account_label.clone()));
        let err = Register::account(dup_account).execute(&authority, &mut tx);
        assert!(err.is_err(), "duplicate label must raise error");
        // Unregister removes label mapping.
        Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister account");
        assert!(
            tx.world.accounts.get(&account_id).is_none(),
            "account should be removed from world"
        );
        assert!(
            tx.world.account_rekey_records.get(&account_label).is_none(),
            "label record must be removed on unregister"
        );
        assert!(
            tx.world.account_aliases.get(&account_label).is_none(),
            "alias index must be removed on unregister"
        );
    }
    #[test]
    fn register_domainless_account_indexes_alias() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let account_label = AccountAlias::domainless(
            "primary".parse::<Name>().expect("label"),
            DataSpaceId::UNIVERSAL,
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_account_alias_manage_permissions(&mut tx, &authority, &account_label);
        seed_account_alias_lease_record(&mut tx, &account_id, &account_label);
        Register::account(Account::new(account_id.clone()).with_label(Some(account_label.clone())))
            .execute(&authority, &mut tx)
            .expect("register domainless account");
        let account = tx.world.account(&account_id).expect("account should exist");
        assert_eq!(account.label(), Some(&account_label));
        assert_eq!(
            tx.world.account_aliases.get(&account_label),
            Some(&account_id)
        );
    }
    #[test]
    fn register_domainless_account_emits_direct_created_event() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register domainless account");
        let created = tx
            .world
            .internal_event_buf
            .iter()
            .find_map(|event| match event.as_ref() {
                DataEvent::Account(AccountEvent::Created(created))
                    if created.account.id() == &account_id =>
                {
                    Some(created.clone())
                }
                _ => None,
            })
            .expect("account created event");
        assert_eq!(created.account.id(), &account_id);
        assert!(tx.world.internal_event_buf.iter().all(|event| {
            !matches!(event.as_ref(), DataEvent::Domain(DomainEvent::Account(_)))
        }));
    }
    #[test]
    fn register_existing_plain_account_returns_repetition_error() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        let error = Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect_err("explicit duplicate registration must fail");
        assert_eq!(
            error,
            InstructionExecutionError::Repetition(RepetitionError {
                instruction: InstructionType::Register,
                id: IdBox::AccountId(account_id),
            })
        );
    }
    #[test]
    fn register_account_with_label_still_emits_direct_created_event() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let account_label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease_record(&mut tx, &account_id, &account_label);
        Register::account(Account::new(account_id.clone()).with_label(Some(account_label)))
            .execute(&authority, &mut tx)
            .expect("register account with label");
        let created = tx
            .world
            .internal_event_buf
            .iter()
            .find_map(|event| match event.as_ref() {
                DataEvent::Account(AccountEvent::Created(created))
                    if created.account.id() == &account_id =>
                {
                    Some(created.clone())
                }
                _ => None,
            })
            .expect("account created event");
        assert_eq!(created.account.id(), &account_id);
        assert!(tx.world.internal_event_buf.iter().all(|event| {
            !matches!(event.as_ref(), DataEvent::Domain(DomainEvent::Account(_)))
        }));
    }
    #[test]
    fn register_account_with_label_requires_active_sns_lease() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        let err = Register::account(Account::new(account_id.clone()).with_label(Some(label)))
            .execute(&authority, &mut tx)
            .expect_err("alias lease should be required");
        assert!(
            instruction_error_contains(&err, "active SNS lease"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn register_account_with_label_rejects_lease_owned_by_another_account() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        let lease_owner = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease(&mut tx, &lease_owner, &label);
        let err =
            Register::account(Account::new(account_id.clone()).with_label(Some(label.clone())))
                .execute(&authority, &mut tx)
                .expect_err("another account's lease must not authorize registration");
        assert!(
            instruction_error_contains(&err, "owned by another account"),
            "unexpected error: {err}"
        );
        assert!(tx.world.account(&account_id).is_err());
        assert!(tx.world.account_aliases.get(&label).is_none());
    }
    #[test]
    fn register_account_with_retail_aliases_requires_active_sns_lease() {
        let authority = (*ALICE_ID).clone();
        let state = test_state_with_authority(&authority);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let (paynet, cbuae) = install_retail_dataspace_catalog(&mut tx);
        for alias in retail_account_aliases(paynet, cbuae) {
            let account_id = AccountId::new(checked_keypair().public_key().clone());
            seed_account_alias_manage_permissions(&mut tx, &authority, &alias);
            let err =
                Register::account(Account::new(account_id.clone()).with_label(Some(alias.clone())))
                    .execute(&authority, &mut tx)
                    .expect_err("retail aliases must require an SNS lease");
            assert!(
                instruction_error_contains(&err, "active SNS lease"),
                "unexpected error for {alias:?}: {err}"
            );
            assert!(tx.world.account_aliases.get(&alias).is_none());
        }
    }
    #[test]
    fn set_account_label_relabels_existing_single_key_account() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let old_label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let new_label = alias_in_domain(&domain_id, "treasury".parse::<Name>().unwrap());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let new_account = Account::new(account_id.clone()).with_label(Some(old_label.clone()));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_account_alias_manage_permissions(&mut tx, &authority, &old_label);
        seed_account_alias_lease_record(&mut tx, &account_id, &old_label);
        seed_account_alias_lease_record(&mut tx, &account_id, &new_label);
        Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect("register account with initial label");
        CasTestPrimaryAccountAlias {
            account: account_id.clone(),
            alias: Some(new_label.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("relabel existing account");
        assert_eq!(
            tx.world.account_aliases.get(&old_label),
            Some(&account_id),
            "primary CAS must retain the former alias as an additional binding"
        );
        assert!(
            tx.world.account_rekey_records.get(&old_label).is_some(),
            "primary CAS must retain former alias continuity"
        );
        assert_eq!(
            tx.world.account_aliases.get(&new_label),
            Some(&account_id),
            "new alias index should be inserted"
        );
        assert!(
            tx.world.account_rekey_records.get(&new_label).is_some(),
            "new rekey record should be inserted"
        );
        assert_eq!(
            tx.world
                .account(&account_id)
                .expect("account should exist")
                .label(),
            Some(&new_label),
            "account should expose the updated label"
        );
    }
    #[test]
    fn primary_alias_cas_allows_domainful_alias_without_domain_link() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let label = alias_in_domain(&domain_id, "treasury".parse::<Name>().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register domainless account");
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease_record(&mut tx, &account_id, &label);
        CasTestPrimaryAccountAlias {
            account: account_id.clone(),
            alias: Some(label.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("domainful alias should no longer require a domain link");
        assert_eq!(tx.world.account_aliases.get(&label), Some(&account_id));
        assert_eq!(
            tx.world
                .account(&account_id)
                .expect("account should exist")
                .label(),
            Some(&label)
        );
    }
    #[test]
    fn primary_alias_setup_rejects_stale_non_empty_binding() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let stale_owner = AccountId::new(checked_keypair().public_key().clone());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world
            .account_aliases
            .insert(label.clone(), stale_owner.clone());
        tx.world.account_rekey_records.insert(
            label.clone(),
            AccountRekeyRecord::new(label.clone(), stale_owner.clone()),
        );
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease_record(&mut tx, &account_id, &label);
        let error = CasTestPrimaryAccountAlias {
            account: account_id.clone(),
            alias: Some(label.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("declarative setup must not reclaim a non-empty binding");
        assert!(instruction_error_contains(&error, "alias.binding.conflict"));
        assert_eq!(
            tx.world.account_aliases.get(&label),
            Some(&stale_owner),
            "conflicting setup must preserve the stale binding for explicit remediation"
        );
        assert_eq!(
            tx.world
                .account_rekey_records
                .get(&label)
                .expect("rekey record should exist")
                .active_account_id,
            stale_owner,
            "conflicting setup must preserve continuity state"
        );
    }
    #[test]
    fn bind_account_alias_requires_active_sns_lease() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let alias = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        let err = RebindAccountAlias::new(
            resolved_account_alias(&tx, &alias),
            account_id.clone(),
            account_id,
        )
        .execute(&authority, &mut tx)
        .expect_err("alias lease should be required");
        assert!(
            instruction_error_contains(&err, "not found"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn alias_binding_and_primary_alias_reject_lease_owned_by_another_account() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        let lease_owner = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let alias = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        seed_account_alias_lease(&mut tx, &lease_owner, &alias);
        for err in [
            EnsureTestAccountAliasBinding {
                account: account_id.clone(),
                alias: Some(alias.clone()),
                lease_expiry_ms: None,
            }
            .execute(&authority, &mut tx)
            .expect_err("another account's lease must not authorize an alias binding"),
            CasTestPrimaryAccountAlias {
                account: account_id.clone(),
                alias: Some(alias.clone()),
                lease_expiry_ms: None,
            }
            .execute(&authority, &mut tx)
            .expect_err("another account's lease must not authorize a primary alias"),
        ] {
            assert!(
                instruction_error_contains(&err, "alias.owner.conflict"),
                "unexpected error: {err}"
            );
        }
        assert!(tx.world.account_aliases.get(&alias).is_none());
        assert!(
            tx.world
                .account(&account_id)
                .expect("account")
                .label()
                .is_none()
        );
    }
    #[test]
    fn account_alias_mutations_reject_expired_leases() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let existing_id = AccountId::new(checked_keypair().public_key().clone());
        let registration_id = AccountId::new(checked_keypair().public_key().clone());
        let registration_alias =
            alias_in_domain(&domain_id, "register_expired".parse::<Name>().unwrap());
        let binding_alias = alias_in_domain(&domain_id, "binding_expired".parse::<Name>().unwrap());
        let primary_alias = alias_in_domain(&domain_id, "primary_expired".parse::<Name>().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        Register::account(Account::new(existing_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register existing account");
        seed_expired_account_alias_lease_record(&mut tx, &registration_id, &registration_alias);
        seed_expired_account_alias_lease_record(&mut tx, &existing_id, &binding_alias);
        seed_expired_account_alias_lease_record(&mut tx, &existing_id, &primary_alias);
        let registration_err = Register::account(
            Account::new(registration_id.clone()).with_label(Some(registration_alias.clone())),
        )
        .execute(&authority, &mut tx)
        .expect_err("an expired registration lease must reject");
        assert!(
            instruction_error_contains(&registration_err, "active SNS lease"),
            "unexpected registration error: {registration_err}"
        );
        let binding_err =
            EnsureTestAccountAliasBinding::bind(existing_id.clone(), binding_alias.clone(), None)
                .execute(&authority, &mut tx)
                .expect_err("an expired binding lease must reject");
        let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            binding_message,
        )) = &binding_err
        else {
            panic!("unexpected expired-binding error: {binding_err:?}");
        };
        assert!(
            binding_message.contains("alias.lifecycle.conflict"),
            "unexpected expired-binding payload: {binding_message}"
        );
        let primary_err =
            CasTestPrimaryAccountAlias::bind(existing_id.clone(), primary_alias.clone(), None)
                .execute(&authority, &mut tx)
                .expect_err("an expired primary-alias lease must reject");
        let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            primary_message,
        )) = &primary_err
        else {
            panic!("unexpected expired-primary error: {primary_err:?}");
        };
        assert!(
            primary_message.contains("alias.lifecycle.conflict"),
            "unexpected expired-primary payload: {primary_message}"
        );
        assert!(tx.world.account(&registration_id).is_err());
        assert!(tx.world.account_aliases.get(&registration_alias).is_none());
        assert!(tx.world.account_aliases.get(&binding_alias).is_none());
        assert!(tx.world.account_aliases.get(&primary_alias).is_none());
        assert!(
            tx.world
                .account(&existing_id)
                .expect("existing account")
                .label()
                .is_none()
        );
    }
    #[test]
    fn account_alias_binding_instructions_cannot_bypass_paid_sns_renewal() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let alias = alias_in_domain(&domain_id, "renewal".parse::<Name>().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        seed_account_alias_lease_record(&mut tx, &account_id, &alias);
        for err in [
            EnsureTestAccountAliasBinding::bind(account_id.clone(), alias.clone(), Some(20))
                .execute(&authority, &mut tx)
                .expect_err("binding must not renew an SNS lease"),
            CasTestPrimaryAccountAlias::bind(account_id.clone(), alias.clone(), Some(20))
                .execute(&authority, &mut tx)
                .expect_err("primary binding must not renew an SNS lease"),
            EnsureTestAccountAliasBinding {
                account: account_id.clone(),
                alias: None,
                lease_expiry_ms: Some(20),
            }
            .execute(&authority, &mut tx)
            .expect_err("clear plus lease expiry must be rejected"),
            CasTestPrimaryAccountAlias {
                account: account_id.clone(),
                alias: None,
                lease_expiry_ms: Some(20),
            }
            .execute(&authority, &mut tx)
            .expect_err("primary clear plus lease expiry must be rejected"),
        ] {
            let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                message,
            )) = err
            else {
                panic!("unexpected error: {err:?}");
            };
            assert!(
                message.contains("RenewAliasLease") || message.contains("requires alias binding"),
                "unexpected error: {message}"
            );
        }
        assert!(tx.world.account_aliases.get(&alias).is_none());
        assert!(
            tx.world
                .account(&account_id)
                .expect("account")
                .label()
                .is_none()
        );
        let selector = crate::sns::selector_for_account_alias(&alias, &tx.nexus.dataspace_catalog)
            .expect("selector");
        let bytes = tx
            .world
            .smart_contract_state
            .get(&crate::sns::record_storage_key(&selector))
            .expect("lease record");
        let mut slice = bytes.as_slice();
        let record = NameRecordV1::decode(&mut slice).expect("decode lease record");
        assert_eq!(record.expires_at_ms, u64::MAX);
    }
    #[test]
    fn bind_account_alias_in_retail_namespace_requires_active_sns_lease() {
        let authority = (*ALICE_ID).clone();
        let state = test_state_with_authority(&authority);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let (paynet, _) = install_retail_dataspace_catalog(&mut tx);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let alias = AccountAlias::domainless("bindretail".parse::<Name>().expect("label"), paynet);
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        seed_account_alias_manage_permissions(&mut tx, &authority, &alias);
        let err = RebindAccountAlias::new(
            resolved_account_alias(&tx, &alias),
            account_id.clone(),
            account_id.clone(),
        )
        .execute(&authority, &mut tx)
        .expect_err("retail alias binding must require an SNS lease");
        assert!(
            instruction_error_contains(&err, "not found"),
            "unexpected error: {err}"
        );
        assert!(tx.world.account_aliases.get(&alias).is_none());
    }
    #[test]
    fn retail_account_alias_rejects_asset_alias_permission() {
        let state = test_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let (paynet, _) = install_retail_dataspace_catalog(&mut tx);
        let hbl = DomainId::try_new("hbl", "paynet").expect("hbl domain");
        let alias = alias_in_dataspace_domain(&hbl, paynet, "cbdc".parse::<Name>().expect("label"));
        let current_account_id = AccountId::new(checked_keypair().public_key().clone());
        let replacement_account_id = AccountId::new(checked_keypair().public_key().clone());
        for account_id in [&current_account_id, &replacement_account_id] {
            let account = Account {
                id: account_id.clone(),
                metadata: Metadata::default(),
                label: None,
                uaid: None,
                opaque_ids: Vec::new(),
            };
            let (account_id, account_value) = account.into_key_value();
            tx.world.accounts.insert(account_id, account_value);
        }
        tx.world
            .insert_account_alias_binding(alias.clone(), current_account_id.clone());
        tx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(
                alias.clone(),
                current_account_id.clone(),
            ));
        seed_account_alias_lease_record(&mut tx, &replacement_account_id, &alias);
        tx.world.add_account_permission(
            &current_account_id,
            Permission::from(CanManageAssetDefinitionAlias {
                scope: AssetDefinitionAliasPermissionScope::Domain(hbl.clone()),
            }),
        );
        let err = RebindAccountAlias::new(
            resolved_account_alias(&tx, &alias),
            current_account_id.clone(),
            replacement_account_id.clone(),
        )
        .execute(&current_account_id, &mut tx)
        .expect_err("asset-definition alias permission must not authorize account aliases");
        assert!(
            instruction_error_contains(&err, "exact management permission"),
            "unexpected error: {err}"
        );
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&current_account_id),
            "rejected mutation must preserve the original alias binding"
        );
        tx.world.add_account_permission(
            &current_account_id,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(hbl),
            }),
        );
        RebindAccountAlias::new(
            resolved_account_alias(&tx, &alias),
            current_account_id.clone(),
            replacement_account_id.clone(),
        )
        .execute(&current_account_id, &mut tx)
        .expect("exact domain permission should authorize the alias mutation");
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&replacement_account_id)
        );
        assert_eq!(
            tx.world
                .account_rekey_records
                .get(&alias)
                .expect("rekey record should follow alias")
                .active_account_id,
            replacement_account_id
        );
    }
    #[test]
    fn cbdc_fi_account_alias_management_isolated_by_exact_domain() {
        let authority = (*ALICE_ID).clone();
        let state = test_state_with_authority(&authority);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let retail = DataSpaceId::new(10);
        install_dataspace_catalog_with_lane(&mut tx, retail, "sbp", LaneVisibility::Public);
        let hbl = DomainId::try_new("hbl", "sbp").expect("HBL alias domain");
        let ubl = DomainId::try_new("ubl", "sbp").expect("UBL alias domain");
        let hbl_alias = alias_in_dataspace_domain(
            &hbl,
            retail,
            "customerhbl".parse::<Name>().expect("HBL alias label"),
        );
        let ubl_alias = alias_in_dataspace_domain(
            &ubl,
            retail,
            "customerubl".parse::<Name>().expect("UBL alias label"),
        );
        let hbl_secondary_alias = alias_in_dataspace_domain(
            &hbl,
            retail,
            "secondaryhbl"
                .parse::<Name>()
                .expect("secondary HBL alias label"),
        );
        let domainless_alias =
            AccountAlias::domainless("retailroot".parse::<Name>().expect("root alias"), retail);
        let target = AccountId::new(checked_keypair().public_key().clone());
        let replacement = AccountId::new(checked_keypair().public_key().clone());
        for account in [&target, &replacement] {
            Register::account(Account::new(account.clone()))
                .execute(&authority, &mut tx)
                .expect("register alias target");
        }
        for alias in [
            &hbl_alias,
            &ubl_alias,
            &hbl_secondary_alias,
            &domainless_alias,
        ] {
            seed_account_alias_lease_record(&mut tx, &target, alias);
        }
        let hbl_permission: Permission = CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(hbl.clone()),
        }
        .into();
        tx.world
            .add_account_permission(&authority, hbl_permission.clone());
        EnsureTestAccountAliasBinding {
            account: target.clone(),
            alias: Some(hbl_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("exact HBL domain permission must authorize an HBL alias");
        for forbidden_alias in [&ubl_alias, &domainless_alias] {
            let err = EnsureTestAccountAliasBinding {
                account: target.clone(),
                alias: Some(forbidden_alias.clone()),
                lease_expiry_ms: None,
            }
            .execute(&authority, &mut tx)
            .expect_err("HBL domain permission must not authorize another alias scope");
            assert!(
                instruction_error_contains(&err, "alias.setup.authority_forbidden"),
                "unexpected cross-scope error: {err}"
            );
            assert!(
                tx.world.account_aliases.get(forbidden_alias).is_none(),
                "rejected cross-scope alias must remain unbound"
            );
        }
        tx.world
            .insert_account_alias_binding(ubl_alias.clone(), target.clone());
        tx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(
                ubl_alias.clone(),
                target.clone(),
            ));
        let err = RebindAccountAlias::new(
            resolved_account_alias(&tx, &ubl_alias),
            target.clone(),
            replacement,
        )
        .execute(&authority, &mut tx)
        .expect_err("HBL authority must not rebind a UBL secondary alias");
        assert!(
            instruction_error_contains(&err, "exact management permission"),
            "unexpected secondary-rebind error: {err}"
        );
        assert_eq!(
            tx.world.account_aliases.get(&hbl_alias),
            Some(&target),
            "secondary rebind must preflight every alias before mutating"
        );
        assert_eq!(tx.world.account_aliases.get(&ubl_alias), Some(&target));
        tx.world.remove_account_alias_binding(&ubl_alias);
        tx.world.remove_account_rekey_record(&ubl_alias);
        assert!(
            tx.world
                .remove_account_permission(&authority, &hbl_permission),
            "HBL permission fixture should be removable"
        );
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(retail),
            }),
        );
        for forbidden_alias in [&hbl_secondary_alias, &ubl_alias] {
            let err = EnsureTestAccountAliasBinding {
                account: target.clone(),
                alias: Some(forbidden_alias.clone()),
                lease_expiry_ms: None,
            }
            .execute(&authority, &mut tx)
            .expect_err("dataspace permission must not authorize a domainful FI alias");
            assert!(
                instruction_error_contains(&err, "alias.setup.authority_forbidden"),
                "unexpected domainful-alias error: {err}"
            );
        }
        EnsureTestAccountAliasBinding {
            account: target.clone(),
            alias: Some(domainless_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("dataspace permission must authorize a domainless alias");
        assert_eq!(
            tx.world.account_aliases.get(&domainless_alias),
            Some(&target)
        );
        assert_eq!(tx.world.account_aliases.get(&hbl_alias), Some(&target));
        assert!(tx.world.account_aliases.get(&hbl_secondary_alias).is_none());
        assert!(tx.world.account_aliases.get(&ubl_alias).is_none());
    }
    #[test]
    fn cbdc_retail_account_rejects_cross_fi_secondary_alias_and_repoint() {
        let authority = (*ALICE_ID).clone();
        let state = test_state_with_authority(&authority);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let retail = DataSpaceId::new(10);
        install_dataspace_catalog_with_lane(&mut tx, retail, "sbp", LaneVisibility::Public);
        let hbl = DomainId::try_new("hbl", "sbp").expect("HBL alias domain");
        let ubl = DomainId::try_new("ubl", "sbp").expect("UBL alias domain");
        let hbl_home_alias = alias_in_dataspace_domain(
            &hbl,
            retail,
            "homehbl".parse::<Name>().expect("HBL home alias label"),
        );
        let hbl_secondary_alias = alias_in_dataspace_domain(
            &hbl,
            retail,
            "secondaryhbl"
                .parse::<Name>()
                .expect("HBL secondary alias label"),
        );
        let hbl_foreign_target_alias = alias_in_dataspace_domain(
            &hbl,
            retail,
            "foreignhbl"
                .parse::<Name>()
                .expect("HBL foreign-target alias label"),
        );
        let ubl_home_alias = alias_in_dataspace_domain(
            &ubl,
            retail,
            "homeubl".parse::<Name>().expect("UBL home alias label"),
        );
        let hbl_account = AccountId::new(checked_keypair().public_key().clone());
        let ubl_account = AccountId::new(checked_keypair().public_key().clone());
        let unhomed_account = AccountId::new(checked_keypair().public_key().clone());
        for account in [&hbl_account, &ubl_account, &unhomed_account] {
            Register::account(Account::new(account.clone()))
                .execute(&authority, &mut tx)
                .expect("register retail account");
        }
        for alias in [&hbl_home_alias, &hbl_secondary_alias] {
            seed_account_alias_lease_record(&mut tx, &hbl_account, alias);
        }
        seed_account_alias_lease_record(&mut tx, &ubl_account, &hbl_foreign_target_alias);
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(hbl),
            }),
        );
        EnsureTestAccountAliasBinding {
            account: hbl_account.clone(),
            alias: Some(hbl_home_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("bind HBL home alias");
        EnsureTestAccountAliasBinding {
            account: hbl_account.clone(),
            alias: Some(hbl_secondary_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("same-FI secondary aliases remain supported");
        tx.world
            .insert_account_alias_binding(ubl_home_alias.clone(), ubl_account.clone());
        tx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(
                ubl_home_alias.clone(),
                ubl_account.clone(),
            ));
        seed_account_alias_lease_record(&mut tx, &ubl_account, &ubl_home_alias);
        let err = EnsureTestAccountAliasBinding {
            account: ubl_account.clone(),
            alias: Some(hbl_foreign_target_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("HBL must not add a secondary alias to a UBL-home account");
        assert!(
            instruction_error_contains(&err, "jointly-authorized migration"),
            "unexpected cross-FI secondary-binding error: {err}"
        );
        assert!(
            tx.world
                .account_aliases
                .get(&hbl_foreign_target_alias)
                .is_none(),
            "rejected foreign-home secondary alias must remain unbound"
        );
        let err = EnsureTestAccountAliasBinding {
            account: ubl_account.clone(),
            alias: Some(hbl_home_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("HBL must not repoint an existing alias to a UBL-home account");
        assert!(
            instruction_error_contains(&err, "alias.owner.conflict"),
            "unexpected cross-FI repoint error: {err}"
        );
        assert_eq!(
            tx.world.account_aliases.get(&hbl_home_alias),
            Some(&hbl_account),
            "rejected cross-FI repoint must preserve the HBL binding"
        );
        assert_eq!(
            tx.world.account_aliases.get(&ubl_home_alias),
            Some(&ubl_account),
            "rejected cross-FI repoint must preserve the UBL home"
        );
        tx.world.remove_account_alias_binding(&hbl_secondary_alias);
        tx.world.remove_account_rekey_record(&hbl_secondary_alias);
        let err = EnsureTestAccountAliasBinding {
            account: unhomed_account,
            alias: Some(hbl_home_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("repointing must not strand the previous account without an FI home");
        assert!(
            instruction_error_contains(&err, "alias.owner.conflict"),
            "unexpected last-home repoint error: {err}"
        );
        assert_eq!(
            tx.world.account_aliases.get(&hbl_home_alias),
            Some(&hbl_account),
            "rejected last-home repoint must preserve its source binding"
        );
    }
    #[test]
    fn clearing_primary_status_keeps_retail_home_binding_and_blocks_cross_fi_setup() {
        let state = test_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let retail = DataSpaceId::new(10);
        install_dataspace_catalog_with_lane(&mut tx, retail, "sbp", LaneVisibility::Public);
        let hbl = DomainId::try_new("hbl", "sbp").expect("HBL alias domain");
        let ubl = DomainId::try_new("ubl", "sbp").expect("UBL alias domain");
        let hbl_manager = AccountId::new(checked_keypair().public_key().clone());
        let ubl_manager = AccountId::new(checked_keypair().public_key().clone());
        let customer = AccountId::new(checked_keypair().public_key().clone());
        for account in [&hbl_manager, &ubl_manager, &customer] {
            Register::account(Account::new(account.clone()))
                .execute(&hbl_manager, &mut tx)
                .expect("register CBDC alias fixture account");
        }
        let hbl_alias = alias_in_dataspace_domain(
            &hbl,
            retail,
            "switchhbl".parse::<Name>().expect("HBL alias label"),
        );
        let ubl_alias = alias_in_dataspace_domain(
            &ubl,
            retail,
            "homeubl".parse::<Name>().expect("UBL alias label"),
        );
        tx.world
            .account_mut(&customer)
            .expect("customer account")
            .set_label(Some(ubl_alias.clone()));
        tx.world
            .insert_account_alias_binding(ubl_alias.clone(), customer.clone());
        tx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(
                ubl_alias.clone(),
                customer.clone(),
            ));
        tx.world.add_account_permission(
            &ubl_manager,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(ubl),
            }),
        );
        tx.world.add_account_permission(
            &hbl_manager,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(hbl),
            }),
        );
        seed_account_alias_lease_record(&mut tx, &customer, &hbl_alias);
        CasTestPrimaryAccountAlias::clear(customer.clone())
            .execute(&ubl_manager, &mut tx)
            .expect("explicit primary CAS may clear status without unbinding the FI home");
        assert_eq!(tx.world.account(&customer).expect("customer").label(), None);
        assert_eq!(tx.world.account_aliases.get(&ubl_alias), Some(&customer));
        let bind_err = EnsureTestAccountAliasBinding {
            account: customer.clone(),
            alias: Some(hbl_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&hbl_manager, &mut tx)
        .expect_err("HBL manager must not bind while the UBL home remains bound");
        assert!(
            bind_err
                .to_string()
                .contains("jointly-authorized migration"),
            "unexpected cross-FI bind error: {bind_err}"
        );
        assert!(tx.world.account_aliases.get(&hbl_alias).is_none());
        assert_eq!(tx.world.account_aliases.get(&ubl_alias), Some(&customer));
    }
    #[test]
    fn cbdc_retail_same_fi_primary_rotation_remains_supported() {
        let authority = (*ALICE_ID).clone();
        let state = test_state_with_authority(&authority);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let retail = DataSpaceId::new(10);
        install_dataspace_catalog_with_lane(&mut tx, retail, "sbp", LaneVisibility::Public);
        let ubl = DomainId::try_new("ubl", "sbp").expect("UBL alias domain");
        let old_alias = alias_in_dataspace_domain(
            &ubl,
            retail,
            "oldubl".parse::<Name>().expect("old UBL alias label"),
        );
        let new_alias = alias_in_dataspace_domain(
            &ubl,
            retail,
            "newubl".parse::<Name>().expect("new UBL alias label"),
        );
        let customer = AccountId::new(checked_keypair().public_key().clone());
        Register::account(Account::new(customer.clone()))
            .execute(&authority, &mut tx)
            .expect("register UBL customer");
        tx.world
            .account_mut(&customer)
            .expect("customer account")
            .set_label(Some(old_alias.clone()));
        tx.world
            .insert_account_alias_binding(old_alias.clone(), customer.clone());
        tx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(
                old_alias.clone(),
                customer.clone(),
            ));
        seed_account_alias_lease_record(&mut tx, &customer, &new_alias);
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(ubl),
            }),
        );
        EnsureTestAccountAliasBinding {
            account: customer.clone(),
            alias: Some(new_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("add a same-FI secondary alias before rotation");
        CasTestPrimaryAccountAlias {
            account: customer.clone(),
            alias: Some(new_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("atomically rotate the primary alias within UBL");
        assert_eq!(
            tx.world.account(&customer).expect("customer").label(),
            Some(&new_alias)
        );
        assert_eq!(tx.world.account_aliases.get(&old_alias), Some(&customer));
        assert_eq!(tx.world.account_aliases.get(&new_alias), Some(&customer));
    }
    #[test]
    fn cleared_primary_status_does_not_enable_cross_fi_replacement() {
        let authority = (*ALICE_ID).clone();
        let state = test_state_with_authority(&authority);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let retail = DataSpaceId::new(10);
        install_dataspace_catalog_with_lane(&mut tx, retail, "sbp", LaneVisibility::Public);
        let hbl = DomainId::try_new("hbl", "sbp").expect("HBL alias domain");
        let ubl = DomainId::try_new("ubl", "sbp").expect("UBL alias domain");
        let hbl_alias = alias_in_dataspace_domain(
            &hbl,
            retail,
            "replacementhbl".parse::<Name>().expect("HBL alias label"),
        );
        let ubl_alias = alias_in_dataspace_domain(
            &ubl,
            retail,
            "primaryubl".parse::<Name>().expect("UBL alias label"),
        );
        let target = AccountId::new(checked_keypair().public_key().clone());
        Register::account(Account::new(target.clone()))
            .execute(&authority, &mut tx)
            .expect("register alias target");
        tx.world
            .account_mut(&target)
            .expect("alias target")
            .set_label(Some(ubl_alias.clone()));
        tx.world
            .insert_account_alias_binding(ubl_alias.clone(), target.clone());
        tx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(
                ubl_alias.clone(),
                target.clone(),
            ));
        seed_account_alias_lease_record(&mut tx, &target, &hbl_alias);
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(hbl),
            }),
        );
        let err = CasTestPrimaryAccountAlias {
            account: target.clone(),
            alias: Some(hbl_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("HBL permission must not remove an existing UBL primary alias");
        assert!(
            instruction_error_contains(&err, "jointly-authorized migration"),
            "unexpected primary-replacement error: {err}"
        );
        assert_eq!(
            tx.world.account(&target).expect("alias target").label(),
            Some(&ubl_alias)
        );
        assert_eq!(tx.world.account_aliases.get(&ubl_alias), Some(&target));
        assert!(tx.world.account_aliases.get(&hbl_alias).is_none());
        let err = CasTestPrimaryAccountAlias {
            account: target.clone(),
            alias: None,
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("HBL permission must not clear an existing UBL primary alias");
        assert!(
            instruction_error_contains(&err, "exact management permission"),
            "unexpected primary-clear error: {err}"
        );
        assert_eq!(tx.world.account_aliases.get(&ubl_alias), Some(&target));
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(ubl),
            }),
        );
        CasTestPrimaryAccountAlias::clear(target.clone())
            .execute(&authority, &mut tx)
            .expect("primary status may clear while the UBL home binding remains");
        let err = CasTestPrimaryAccountAlias {
            account: target.clone(),
            alias: Some(hbl_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("cross-FI primary migration requires an explicit joint instruction");
        assert!(
            instruction_error_contains(&err, "jointly-authorized migration"),
            "unexpected cross-FI primary migration error: {err}"
        );
        assert_eq!(
            tx.world.account(&target).expect("alias target").label(),
            None
        );
        assert!(tx.world.account_aliases.get(&hbl_alias).is_none());
        assert_eq!(tx.world.account_aliases.get(&ubl_alias), Some(&target));
    }
    #[test]
    fn primary_alias_cas_in_retail_namespace_requires_active_sns_lease() {
        let authority = (*ALICE_ID).clone();
        let state = test_state_with_authority(&authority);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let (_, cbuae) = install_retail_dataspace_catalog(&mut tx);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let alias =
            AccountAlias::domainless("primaryretail".parse::<Name>().expect("label"), cbuae);
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        seed_account_alias_manage_permissions(&mut tx, &authority, &alias);
        let err = CompareAndSetPrimaryAccountAlias::new(
            account_id.clone(),
            None,
            Some(resolved_account_alias(&tx, &alias)),
        )
        .execute(&authority, &mut tx)
        .expect_err("retail primary alias must require an SNS lease");
        assert!(
            instruction_error_contains(&err, "not found"),
            "unexpected error: {err}"
        );
        assert!(tx.world.account_aliases.get(&alias).is_none());
    }
    #[test]
    fn set_account_label_binds_existing_multisig_account_with_rekey_record() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let member_a = MultisigMember::new(checked_keypair().public_key().clone(), 1)
            .expect("multisig member");
        let member_b = MultisigMember::new(checked_keypair().public_key().clone(), 1)
            .expect("multisig member");
        let policy = MultisigPolicy::new(2, vec![member_a, member_b]).expect("multisig policy");
        let account_id = AccountId::new_multisig(policy);
        let account_label = alias_in_domain(&domain_id, "cbdc".parse::<Name>().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register unlabeled multisig account");
        seed_account_alias_lease(&mut tx, &account_id, &account_label);
        CasTestPrimaryAccountAlias {
            account: account_id.clone(),
            alias: Some(account_label.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("bind label to existing multisig account");
        assert_eq!(
            tx.world.account_aliases.get(&account_label),
            Some(&account_id),
            "multisig alias index should be inserted"
        );
        let rekey_record = tx
            .world
            .account_rekey_records
            .get(&account_label)
            .expect("multisig aliases should create rekey records");
        assert_eq!(
            rekey_record.active_account_id, account_id,
            "rekey record should point at the multisig account"
        );
        assert!(
            rekey_record.active_signatory.is_none(),
            "multisig rekey records should not invent a single-key signatory"
        );
        assert_eq!(
            tx.world
                .account(&account_id)
                .expect("account should exist")
                .label(),
            Some(&account_label),
            "multisig account should expose the bound label"
        );
    }
    #[test]
    fn account_rekey_upsert_records_alias_reassignment_provenance() {
        let state = test_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let alias = AccountAlias::domainless(
            "direct-reassignment".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let first = AccountId::new(checked_keypair().public_key().clone());
        let second = AccountId::new(checked_keypair().public_key().clone());
        upsert_account_rekey_record(&mut tx, &alias, &first).expect("initial continuity record");
        upsert_account_rekey_record(&mut tx, &alias, &second).expect("alias reassignment");
        let record = tx
            .world
            .account_rekey_records
            .get(&alias)
            .expect("updated continuity record");
        assert_eq!(record.active_account_id, second);
        assert_eq!(record.previous_account_ids, vec![first]);
        assert_eq!(
            record.transition_provenance,
            vec![AccountRekeyTransitionProvenance::AliasReassignment]
        );
        let active_account_id = record.active_account_id.clone();
        let mismatched_alias = AccountAlias::domainless(
            "mismatched".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        tx.world.account_rekey_records.insert(
            alias.clone(),
            AccountRekeyRecord::new(mismatched_alias, active_account_id),
        );
        let replacement = AccountId::new(checked_keypair().public_key().clone());
        let error = upsert_account_rekey_record(&mut tx, &alias, &replacement)
            .expect_err("mismatched embedded alias must fail closed");
        assert!(error.to_string().contains("mismatched continuity record"));
    }
    #[test]
    fn set_account_label_rejects_account_registrar_repointing_existing_alias() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let domain_owner = (*ALICE_ID).clone();
        let registrar = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &domain_owner);
        seed_account(&mut state, &registrar, &domain_id);
        let alias = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let first_keypair = checked_keypair();
        let first_id = AccountId::new(first_keypair.public_key().clone());
        let second_keypair = checked_keypair();
        let second_id = AccountId::new(second_keypair.public_key().clone());
        let permission: Permission = CanRegisterAccount {
            domain: domain_id.clone(),
        }
        .into();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Grant::account_permission(permission, registrar.clone())
            .execute(&domain_owner, &mut tx)
            .expect("grant registrar permission");
        seed_domainful_alias_manage_permissions(&mut tx, &registrar, &domain_id);
        seed_account_alias_manage_permissions(&mut tx, &domain_owner, &alias);
        Register::account(Account::new(first_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register first account");
        Register::account(Account::new(second_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register second account");
        seed_account_alias_lease(&mut tx, &first_id, &alias);
        CasTestPrimaryAccountAlias {
            account: first_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&domain_owner, &mut tx)
        .expect("seed alias on first account");
        seed_account_alias_lease(&mut tx, &second_id, &alias);
        let error = CasTestPrimaryAccountAlias {
            account: second_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&registrar, &mut tx)
        .expect_err("registrar must use an explicit CAS rebind operation");
        assert!(
            instruction_error_contains(&error, "alias.binding.conflict"),
            "unexpected error: {error}"
        );
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&first_id),
            "conflicting setup must preserve the existing binding"
        );
        assert_eq!(
            tx.world
                .account(&first_id)
                .expect("first account should exist")
                .label(),
            Some(&alias),
            "conflicting setup must preserve the existing primary alias"
        );
        assert_eq!(
            tx.world
                .account(&second_id)
                .expect("second account should exist")
                .label(),
            None,
            "conflicting setup must not modify the requested target"
        );
        let rekey_record = tx
            .world
            .account_rekey_records
            .get(&alias)
            .expect("existing binding should retain its continuity record");
        assert_eq!(
            rekey_record.active_account_id, first_id,
            "rekey record must retain the existing account"
        );
        assert!(rekey_record.previous_account_ids.is_empty());
        assert!(rekey_record.transition_provenance.is_empty());
        assert_eq!(
            rekey_record.active_signatory,
            Some(first_keypair.public_key().clone()),
            "rekey record must retain the existing controller"
        );
    }
    #[test]
    fn set_account_label_rejects_global_registrar_repointing_existing_alias() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let domain_owner = (*ALICE_ID).clone();
        let registrar = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &domain_owner);
        seed_account(&mut state, &registrar, &domain_id);
        let alias = alias_in_domain(&domain_id, "issuance".parse::<Name>().unwrap());
        let first_keypair = checked_keypair();
        let first_id = AccountId::new(first_keypair.public_key().clone());
        let second_keypair = checked_keypair();
        let second_id = AccountId::new(second_keypair.public_key().clone());
        let permission = Permission::new(
            "CanRegisterAccount".parse().expect("permission name"),
            iroha_primitives::json::Json::new(()),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Grant::account_permission(permission, registrar.clone())
            .execute(&domain_owner, &mut tx)
            .expect("grant global registrar permission");
        seed_domainful_alias_manage_permissions(&mut tx, &registrar, &domain_id);
        seed_account_alias_manage_permissions(&mut tx, &domain_owner, &alias);
        Register::account(Account::new(first_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register first account");
        Register::account(Account::new(second_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register second account");
        seed_account_alias_lease(&mut tx, &first_id, &alias);
        CasTestPrimaryAccountAlias {
            account: first_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&domain_owner, &mut tx)
        .expect("seed alias on first account");
        seed_account_alias_lease(&mut tx, &second_id, &alias);
        let error = CasTestPrimaryAccountAlias {
            account: second_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&registrar, &mut tx)
        .expect_err("global registrar must use an explicit CAS rebind operation");
        assert!(instruction_error_contains(&error, "alias.binding.conflict"));
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&first_id),
            "conflicting setup must preserve the existing binding"
        );
        assert_eq!(
            tx.world
                .account(&first_id)
                .expect("first account should exist")
                .label(),
            Some(&alias),
            "conflicting setup must preserve the existing primary alias"
        );
        assert_eq!(
            tx.world
                .account(&second_id)
                .expect("second account should exist")
                .label(),
            None,
            "conflicting setup must not modify the requested target"
        );
    }
    #[test]
    fn bind_account_alias_adds_multiple_aliases_to_existing_multisig_account() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let member_a = MultisigMember::new(checked_keypair().public_key().clone(), 1)
            .expect("multisig member");
        let member_b = MultisigMember::new(checked_keypair().public_key().clone(), 1)
            .expect("multisig member");
        let policy = MultisigPolicy::new(2, vec![member_a, member_b]).expect("multisig policy");
        let account_id = AccountId::new_multisig(policy);
        let banking_label = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let issuance_label = alias_in_domain(&domain_id, "issuance".parse::<Name>().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register unlabeled multisig account");
        seed_account_alias_lease(&mut tx, &account_id, &banking_label);
        seed_account_alias_lease(&mut tx, &account_id, &issuance_label);
        EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(banking_label.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("bind banking alias");
        EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(issuance_label.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("bind issuance alias");
        assert_eq!(
            tx.world.account_aliases.get(&banking_label),
            Some(&account_id),
            "banking alias should resolve to the multisig account"
        );
        assert_eq!(
            tx.world.account_aliases.get(&issuance_label),
            Some(&account_id),
            "issuance alias should resolve to the same multisig account"
        );
        let banking_record = tx
            .world
            .account_rekey_records
            .get(&banking_label)
            .expect("banking alias should create a rekey record");
        assert_eq!(
            banking_record.active_account_id, account_id,
            "banking rekey record should resolve to the multisig account"
        );
        assert!(
            banking_record.active_signatory.is_none(),
            "multisig alias records should not expose a single-key signatory"
        );
        let issuance_record = tx
            .world
            .account_rekey_records
            .get(&issuance_label)
            .expect("issuance alias should create a rekey record");
        assert_eq!(
            issuance_record.active_account_id, account_id,
            "issuance rekey record should resolve to the multisig account"
        );
        assert!(
            issuance_record.active_signatory.is_none(),
            "multisig alias records should not expose a single-key signatory"
        );
        assert!(
            tx.world
                .account(&account_id)
                .expect("account should exist")
                .label()
                .is_none(),
            "binding extra aliases should not overwrite the account's canonical label"
        );
    }
    #[test]
    fn unregister_account_removes_all_account_scoped_permissions() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let contract_deployer = AccountId::new(checked_keypair().public_key().clone());
        let holder = AccountId::new(checked_keypair().public_key().clone());
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("account-cleanup", "universal").expect("asset domain"),
            "cash".parse().expect("asset name"),
        );
        let contract = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("network id"),
            &contract_deployer,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let target = contract.subject_id();
        let permissions = [
            Permission::from(
                iroha_executor_data_model::permission::account::CanReplaceAccountController {
                    account: target.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                    authority: target.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                    contract,
                    entrypoint: "main".to_owned(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetTransferAvailability {
                    account: target.clone(),
                    asset_definition: asset_definition.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetHoldingLimit {
                    account: target.clone(),
                    asset_definition: asset_definition.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::settlement::CanExecuteSettlement {
                    debited_asset: AssetId::new(asset_definition, target.clone()),
                    settlement_id: iroha_data_model::isi::SettlementId::new(target.clone(), "account_cleanup_consent".parse().expect("settlement reference")),
                    intent_hash: Hash::new(b"account cleanup consent"),
                },
            ),
        ];
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        for account in [target.clone(), holder.clone()] {
            Register::account(NewAccount::new(account))
                .execute(&authority, &mut tx)
                .expect("register cleanup fixture account");
        }
        let role_id: RoleId = "ACCOUNT_CLEANUP".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), holder.clone()))
            .execute(&authority, &mut tx)
            .expect("register cleanup fixture role");
        for permission in &permissions {
            Grant::account_permission(permission.clone(), holder.clone())
                .execute(&authority, &mut tx)
                .expect("grant account-scoped permission");
            Grant::role_permission(permission.clone(), role_id.clone())
                .execute(&authority, &mut tx)
                .expect("grant role-scoped permission");
        }
        Unregister::account(target)
            .execute(&authority, &mut tx)
            .expect("unregister target account");
        assert!(
            tx.world
                .account_permissions
                .get(&holder)
                .is_none_or(|held| permissions
                    .iter()
                    .all(|permission| !held.contains(permission))),
            "direct account-scoped permissions must be removed"
        );
        let role = tx.world.roles.get(&role_id).expect("cleanup role remains");
        assert!(
            permissions
                .iter()
                .all(|permission| !role.permissions().any(|candidate| candidate == permission)),
            "role-held account-scoped permissions must be removed"
        );
        assert!(
            permissions
                .iter()
                .all(|permission| !role.permission_epochs().contains_key(permission)),
            "removed role permissions must not retain epochs"
        );
    }
    #[test]
    fn unregister_account_removes_all_bound_aliases() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let primary_label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let bound_label =
            AccountAlias::domainless("public".parse::<Name>().unwrap(), DataSpaceId::UNIVERSAL);
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease_record(&mut tx, &account_id, &primary_label);
        seed_account_alias_lease_record(&mut tx, &account_id, &bound_label);
        Register::account(Account::new(account_id.clone()).with_label(Some(primary_label.clone())))
            .execute(&authority, &mut tx)
            .expect("register account with primary label");
        EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(bound_label.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("bind additional alias");
        Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister account");
        assert!(tx.world.account_aliases.get(&primary_label).is_none());
        assert!(tx.world.account_aliases.get(&bound_label).is_none());
        assert!(tx.world.account_rekey_records.get(&primary_label).is_none());
        assert!(tx.world.account_rekey_records.get(&bound_label).is_none());
        assert!(
            tx.world
                .account_aliases_by_account
                .get(&account_id)
                .is_none(),
            "reverse alias index must be cleared on unregister"
        );
    }
    #[test]
    fn broad_account_alias_binding_clear_is_rejected_without_mutation() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        seed_account(&mut state, &authority, &domain_id);
        let primary_label = alias_in_domain(&domain_id, "primary".parse::<Name>().unwrap());
        let root_alias =
            AccountAlias::domainless("public".parse::<Name>().unwrap(), DataSpaceId::UNIVERSAL);
        let domain_alias = alias_in_domain(&domain_id, "issuance".parse::<Name>().unwrap());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease_record(&mut tx, &account_id, &primary_label);
        seed_account_alias_lease_record(&mut tx, &account_id, &root_alias);
        seed_account_alias_lease_record(&mut tx, &account_id, &domain_alias);
        Register::account(Account::new(account_id.clone()).with_label(Some(primary_label.clone())))
            .execute(&authority, &mut tx)
            .expect("register account with primary label");
        EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(root_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("bind root alias");
        EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(domain_alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect("bind domain alias");
        let error = EnsureTestAccountAliasBinding::clear(account_id.clone())
            .execute(&authority, &mut tx)
            .expect_err("broad secondary-alias clearing is not a lifecycle CAS operation");
        assert!(instruction_error_contains(
            &error,
            "broad alias clearing was removed"
        ));
        assert_eq!(
            tx.world.account_aliases.get(&primary_label),
            Some(&account_id),
            "primary alias binding must remain"
        );
        assert_eq!(tx.world.account_aliases.get(&root_alias), Some(&account_id));
        assert_eq!(
            tx.world.account_aliases.get(&domain_alias),
            Some(&account_id)
        );
        assert!(tx.world.account_rekey_records.get(&root_alias).is_some());
        assert!(tx.world.account_rekey_records.get(&domain_alias).is_some());
        assert_eq!(
            tx.world
                .account(&account_id)
                .expect("account should exist")
                .label(),
            Some(&primary_label),
            "clear must not remove the primary alias"
        );
        let remaining_aliases = tx
            .world
            .account_aliases_by_account
            .get(&account_id)
            .expect("reverse index should remain intact");
        assert_eq!(remaining_aliases.len(), 3);
        assert!(remaining_aliases.contains(&primary_label));
        assert!(remaining_aliases.contains(&root_alias));
        assert!(remaining_aliases.contains(&domain_alias));
    }
    #[test]
    fn alias_setup_rejects_stale_non_empty_binding() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let alias = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let stale_owner = AccountId::new(checked_keypair().public_key().clone());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world
            .account_aliases
            .insert(alias.clone(), stale_owner.clone());
        tx.world.account_rekey_records.insert(
            alias.clone(),
            AccountRekeyRecord::new(alias.clone(), stale_owner.clone()),
        );
        Register::account(Account::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        seed_domainful_alias_manage_permissions(&mut tx, &authority, &domain_id);
        seed_account_alias_lease_record(&mut tx, &account_id, &alias);
        let error = EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("declarative setup must reject stale non-empty binding drift");
        assert!(instruction_error_contains(&error, "alias.binding.conflict"));
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&stale_owner),
            "conflicting setup must preserve the existing binding"
        );
        assert_eq!(
            tx.world
                .account_rekey_records
                .get(&alias)
                .expect("rekey record should exist")
                .active_account_id,
            stale_owner,
            "conflicting setup must preserve continuity state"
        );
    }
    #[test]
    fn bind_account_alias_allows_account_registrar_for_domain() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let domain_owner = (*ALICE_ID).clone();
        let registrar = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &domain_owner);
        seed_account(&mut state, &registrar, &domain_id);
        let alias = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let permission: Permission = CanRegisterAccount {
            domain: domain_id.clone(),
        }
        .into();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Grant::account_permission(permission, registrar.clone())
            .execute(&domain_owner, &mut tx)
            .expect("grant registrar permission");
        seed_domainful_alias_manage_permissions(&mut tx, &registrar, &domain_id);
        Register::account(Account::new(account_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register account");
        seed_account_alias_lease(&mut tx, &account_id, &alias);
        EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&registrar, &mut tx)
        .expect("registrar should bind alias");
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&account_id),
            "registrar-bound alias should resolve to the target account"
        );
    }
    #[test]
    fn bind_account_alias_allows_global_account_registrar() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let domain_owner = (*ALICE_ID).clone();
        let registrar = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &domain_owner);
        seed_account(&mut state, &registrar, &domain_id);
        let alias = alias_in_domain(&domain_id, "issuance".parse::<Name>().unwrap());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let permission = Permission::new(
            "CanRegisterAccount".parse().expect("permission name"),
            iroha_primitives::json::Json::new(()),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Grant::account_permission(permission, registrar.clone())
            .execute(&domain_owner, &mut tx)
            .expect("grant global registrar permission");
        seed_domainful_alias_manage_permissions(&mut tx, &registrar, &domain_id);
        Register::account(Account::new(account_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register account");
        seed_account_alias_lease(&mut tx, &account_id, &alias);
        EnsureTestAccountAliasBinding {
            account: account_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&registrar, &mut tx)
        .expect("global registrar should bind alias");
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&account_id),
            "global-registrar-bound alias should resolve to the target account"
        );
    }
    #[test]
    fn bind_account_alias_rejects_alias_owned_by_different_account_without_registrar_rights() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let domain_owner = (*ALICE_ID).clone();
        let unauthorized = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &domain_owner);
        seed_account(&mut state, &unauthorized, &domain_id);
        let alias = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let first_keypair = checked_keypair();
        let first_id = AccountId::new(first_keypair.public_key().clone());
        let second_keypair = checked_keypair();
        let second_id = AccountId::new(second_keypair.public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_account_alias_manage_permissions(&mut tx, &domain_owner, &alias);
        Register::account(Account::new(first_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register first account");
        Register::account(Account::new(second_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register second account");
        seed_account_alias_lease(&mut tx, &first_id, &alias);
        EnsureTestAccountAliasBinding {
            account: first_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&domain_owner, &mut tx)
        .expect("bind alias to first account");
        let err = EnsureTestAccountAliasBinding {
            account: second_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&unauthorized, &mut tx)
        .expect_err("alias collision should be rejected");
        assert!(
            instruction_error_contains(&err, "alias.owner.conflict"),
            "error should preserve the existing lease-owner conflict: {err}"
        );
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&first_id),
            "existing alias binding must remain unchanged"
        );
    }
    #[test]
    fn bind_account_alias_rejects_account_registrar_repointing_existing_alias() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let domain_owner = (*ALICE_ID).clone();
        let registrar = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &domain_owner);
        seed_account(&mut state, &registrar, &domain_id);
        let alias = alias_in_domain(&domain_id, "banking".parse::<Name>().unwrap());
        let first_keypair = checked_keypair();
        let first_id = AccountId::new(first_keypair.public_key().clone());
        let second_keypair = checked_keypair();
        let second_id = AccountId::new(second_keypair.public_key().clone());
        let permission: Permission = CanRegisterAccount {
            domain: domain_id.clone(),
        }
        .into();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Grant::account_permission(permission, registrar.clone())
            .execute(&domain_owner, &mut tx)
            .expect("grant registrar permission");
        seed_domainful_alias_manage_permissions(&mut tx, &registrar, &domain_id);
        seed_account_alias_manage_permissions(&mut tx, &domain_owner, &alias);
        Register::account(Account::new(first_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register first account");
        Register::account(Account::new(second_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register second account");
        seed_account_alias_lease(&mut tx, &first_id, &alias);
        EnsureTestAccountAliasBinding {
            account: first_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&domain_owner, &mut tx)
        .expect("seed alias on first account");
        seed_account_alias_lease(&mut tx, &second_id, &alias);
        let error = EnsureTestAccountAliasBinding {
            account: second_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&registrar, &mut tx)
        .expect_err("registrar must use an explicit CAS rebind operation");
        assert!(instruction_error_contains(&error, "alias.binding.conflict"));
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&first_id),
            "conflicting setup must preserve the existing binding"
        );
        assert_eq!(
            tx.world
                .account(&first_id)
                .expect("first account should exist")
                .label(),
            None,
            "an additional alias conflict must not alter primary state"
        );
    }
    #[test]
    fn bind_account_alias_rejects_global_registrar_repointing_existing_alias() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let domain_owner = (*ALICE_ID).clone();
        let registrar = (*BOB_ID).clone();
        seed_domain(&mut state, &domain_id, &domain_owner);
        seed_account(&mut state, &registrar, &domain_id);
        let alias = alias_in_domain(&domain_id, "issuance".parse::<Name>().unwrap());
        let first_keypair = checked_keypair();
        let first_id = AccountId::new(first_keypair.public_key().clone());
        let second_keypair = checked_keypair();
        let second_id = AccountId::new(second_keypair.public_key().clone());
        let permission = Permission::new(
            "CanRegisterAccount".parse().expect("permission name"),
            iroha_primitives::json::Json::new(()),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Grant::account_permission(permission, registrar.clone())
            .execute(&domain_owner, &mut tx)
            .expect("grant global registrar permission");
        seed_domainful_alias_manage_permissions(&mut tx, &registrar, &domain_id);
        seed_account_alias_manage_permissions(&mut tx, &domain_owner, &alias);
        Register::account(Account::new(first_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register first account");
        Register::account(Account::new(second_id.clone()))
            .execute(&domain_owner, &mut tx)
            .expect("register second account");
        seed_account_alias_lease(&mut tx, &first_id, &alias);
        EnsureTestAccountAliasBinding {
            account: first_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&domain_owner, &mut tx)
        .expect("seed alias on first account");
        seed_account_alias_lease(&mut tx, &second_id, &alias);
        let error = EnsureTestAccountAliasBinding {
            account: second_id.clone(),
            alias: Some(alias.clone()),
            lease_expiry_ms: None,
        }
        .execute(&registrar, &mut tx)
        .expect_err("global registrar must use an explicit CAS rebind operation");
        assert!(instruction_error_contains(&error, "alias.binding.conflict"));
        assert_eq!(
            tx.world.account_aliases.get(&alias),
            Some(&first_id),
            "conflicting setup must preserve the existing binding"
        );
        assert_eq!(
            tx.world
                .account(&first_id)
                .expect("first account should exist")
                .label(),
            None,
            "an additional alias conflict must not alter primary state"
        );
    }
    #[test]
    fn register_account_rejects_phone_like_label() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("label", "universal").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let account_label = alias_in_domain(&domain_id, "+819398553445".parse::<Name>().unwrap());
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let new_account = Account::new(account_id.clone()).with_label(Some(account_label));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect_err("phone-like label should be rejected");
        assert!(
            err.to_string().contains("raw PII"),
            "error should mention raw PII: {err}"
        );
    }
    #[test]
    fn transfer_domain_rejects_authority_without_ownership() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let users_domain_id: DomainId =
            DomainId::try_new("users", "universal").expect("users domain id");
        let transferred_domain_id: DomainId =
            DomainId::try_new("foo", "universal").expect("foo domain id");
        let user1 = AccountId::new(checked_keypair().public_key().clone());
        let user2 = AccountId::new(checked_keypair().public_key().clone());
        let authority_domain: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        seed_domain(&mut state, &authority_domain, &authority);
        seed_account(&mut state, &authority, &authority_domain);
        seed_domain(&mut state, &users_domain_id, &user1);
        seed_domain(&mut state, &transferred_domain_id, &user1);
        seed_account(&mut state, &user1, &users_domain_id);
        seed_account(&mut state, &user2, &users_domain_id);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = Transfer::domain(user1.clone(), transferred_domain_id.clone(), user2)
            .execute(&authority, &mut tx)
            .expect_err("transfer must fail for authority that does not own source or domain");
        assert!(
            err.to_string()
                .contains("Can't transfer domain of another account"),
            "unexpected transfer error: {err}"
        );
        assert_eq!(
            tx.world
                .domain(&transferred_domain_id)
                .expect("domain should still exist")
                .owned_by(),
            &user1
        );
    }
    #[test]
    fn transfer_domain_rejects_noncanonical_musubi_generation_before_owner_mutation() {
        for generation in [0, 1] {
            let mut state = test_state();
            let source = (*ALICE_ID).clone();
            let destination = (*BOB_ID).clone();
            let domain_id = DomainId::try_new("generation_guard", "universal").expect("domain id");
            seed_domain(&mut state, &domain_id, &source);
            seed_account(&mut state, &source, &domain_id);
            seed_account(&mut state, &destination, &domain_id);
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut transaction = block.transaction();
            transaction
                .world
                .musubi_domain_ownership_generations_mut()
                .insert(domain_id.clone(), generation);
            let error = Transfer::domain(source.clone(), domain_id.clone(), destination.clone())
                .execute(&source, &mut transaction)
                .expect_err("a noncanonical stored generation must fail before transfer");
            assert!(
                error
                    .to_string()
                    .contains("Musubi domain ownership generation is noncanonical"),
                "unexpected generation guard error: {error}"
            );
            assert_eq!(
                transaction
                    .world
                    .domain(&domain_id)
                    .expect("domain remains registered")
                    .owned_by(),
                &source
            );
            assert_eq!(
                transaction
                    .world
                    .musubi_domain_ownership_generations()
                    .get(&domain_id),
                Some(&generation)
            );
        }
    }
    #[test]
    fn register_account_rejects_opaque_ids_without_uaid() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("opaque", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let opaque = OpaqueAccountId::from_hash(Hash::new("opaque::missing-uaid"));
        let new_account = NewAccount {
            id: account_id,
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: vec![opaque],
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect_err("opaque ids without UAID should be rejected");
        assert!(
            err.to_string()
                .contains("Opaque identifiers require a UAID"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn register_account_rejects_duplicate_opaque_ids() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("opaque", "dupes").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let uaid = UniversalAccountId::from_hash(Hash::new("uaid::opaque-dupes"));
        let opaque = OpaqueAccountId::from_hash(Hash::new("opaque::dupe"));
        let new_account = NewAccount {
            id: account_id,
            metadata: Metadata::default(),
            label: None,
            uaid: Some(uaid),
            opaque_ids: vec![opaque, opaque],
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect_err("duplicate opaque ids should be rejected");
        assert!(
            err.to_string().contains("duplicate opaque identifier"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn register_account_rejects_opaque_id_collisions() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("opaque", "collide").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let opaque = OpaqueAccountId::from_hash(Hash::new("opaque::collide"));
        let first_id = AccountId::new(checked_keypair().public_key().clone());
        let second_id = AccountId::new(checked_keypair().public_key().clone());
        let first_uaid = UniversalAccountId::from_hash(Hash::new("uaid::opaque-collide-1"));
        let second_uaid = UniversalAccountId::from_hash(Hash::new("uaid::opaque-collide-2"));
        let first_account = NewAccount {
            id: first_id.clone(),
            metadata: Metadata::default(),
            label: None,
            uaid: Some(first_uaid),
            opaque_ids: vec![opaque],
        };
        let second_account = NewAccount {
            id: second_id.clone(),
            metadata: Metadata::default(),
            label: None,
            uaid: Some(second_uaid),
            opaque_ids: vec![opaque],
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(first_account)
            .execute(&authority, &mut tx)
            .expect("register first account");
        let err = Register::account(second_account)
            .execute(&authority, &mut tx)
            .expect_err("opaque id collisions should be rejected");
        assert!(
            err.to_string().contains("already bound to UAID"),
            "unexpected error: {err}"
        );
        assert_eq!(
            tx.world.opaque_uaids.get(&opaque),
            Some(&first_uaid),
            "opaque id should remain bound to first UAID"
        );
        assert!(
            tx.world.accounts.get(&second_id).is_none(),
            "colliding account must not be inserted"
        );
    }
    #[test]
    fn register_account_rejects_disallowed_algorithms() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("disallowed", "curves").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        {
            let mut guard = state.crypto.write();
            let mut cfg = (**guard).clone();
            cfg.allowed_signing = vec![Algorithm::Ed25519];
            cfg.allowed_curve_ids =
                iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
                    &cfg.allowed_signing,
                );
            *guard = Arc::new(cfg);
        }
        let secp_pair = checked_keypair_with_algorithm(Algorithm::Secp256k1);
        let account_id = AccountId::new(secp_pair.public_key().clone());
        let new_account = Account::new(account_id.clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect_err("registration with disallowed algorithm must fail");
        let err_string = err.to_string();
        assert!(
            err_string.contains("crypto.allowed_signing"),
            "error should reference allowed_signing gating: {err_string}"
        );
    }
    #[cfg(feature = "bls")]
    #[test]
    fn register_account_allows_bls_even_when_not_in_allowed_signing() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("bls", "allowed").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        {
            let mut guard = state.crypto.write();
            let mut cfg = (**guard).clone();
            cfg.allowed_signing = vec![Algorithm::Ed25519];
            cfg.allowed_curve_ids =
                iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
                    &cfg.allowed_signing,
                );
            *guard = Arc::new(cfg);
        }
        let bls_pair = checked_keypair_with_algorithm(Algorithm::BlsNormal);
        let account_id = AccountId::new(bls_pair.public_key().clone());
        let new_account = Account::new(account_id.clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect("BLS controllers should be allowed for consensus accounts");
    }
    #[test]
    fn register_account_rejects_disallowed_curve_ids() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("restricted", "curves").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        {
            let mut guard = state.crypto.write();
            let mut cfg = (**guard).clone();
            cfg.allowed_curve_ids.clear();
            *guard = Arc::new(cfg);
        }
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let new_account = Account::new(account_id.clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect_err("registration with disallowed curve ids must fail");
        let err_string = err.to_string();
        assert!(
            err_string.contains("crypto.curves.allowed_curve_ids"),
            "error should reference curve gating: {err_string}"
        );
    }
    #[test]
    fn register_account_updates_space_directory_bindings() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("spaces", "bindings").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::register_bindings"));
        let dataspace = DataSpaceId::new(17);
        seed_manifest_record(&mut state.world, uaid, dataspace, |record| {
            record.lifecycle.mark_activated(5);
        });
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let new_account = NewAccount::new(account_id.clone()).with_uaid(Some(uaid));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect("register account with UAID");
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        let bindings = view
            .world()
            .uaid_dataspaces()
            .get(&uaid)
            .expect("bindings exist after registration");
        let dataspace_entry = bindings
            .iter()
            .find(|(id, _)| **id == dataspace)
            .expect("dataspace should be present");
        assert!(
            dataspace_entry.1.contains(&account_id),
            "account must be bound to dataspace"
        );
    }
    #[test]
    fn register_account_rejects_duplicate_uaid() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("uaid", "duplicates").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::duplicate"));
        let first_keypair = checked_keypair();
        let first_id = AccountId::new(first_keypair.public_key().clone());
        let first_account = NewAccount::new(first_id.clone()).with_uaid(Some(uaid));
        let second_keypair = checked_keypair();
        let second_id = AccountId::new(second_keypair.public_key().clone());
        let second_account = NewAccount::new(second_id.clone()).with_uaid(Some(uaid));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(first_account)
            .execute(&authority, &mut tx)
            .expect("register first account");
        let err = Register::account(second_account)
            .execute(&authority, &mut tx)
            .expect_err("duplicate UAID must be rejected");
        let err_string = err.to_string();
        assert!(
            err_string.contains("UAID"),
            "error should reference UAID conflict: {err_string}"
        );
        assert_eq!(
            tx.world.uaid_accounts.get(&uaid),
            Some(&first_id),
            "UAID index must retain the first account"
        );
        assert!(
            tx.world.accounts.get(&second_id).is_none(),
            "duplicate account should not be inserted"
        );
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit block");
        let view = state.view();
        assert_eq!(view.world().uaid_accounts().get(&uaid), Some(&first_id));
    }
    #[test]
    fn unregister_account_removes_space_directory_bindings() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("spaces", "cleanup").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::unregister_bindings"));
        let dataspace = DataSpaceId::new(21);
        seed_manifest_record(&mut state.world, uaid, dataspace, |record| {
            record.lifecycle.mark_activated(3);
        });
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let new_account = NewAccount::new(account_id.clone()).with_uaid(Some(uaid));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect("register account");
        Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister account");
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
        let view = state.view();
        assert!(
            view.world().uaid_dataspaces().get(&uaid).is_none(),
            "bindings should be removed after account deletion"
        );
        assert!(
            view.world().uaid_accounts().get(&uaid).is_none(),
            "UAID index should be cleared after account deletion"
        );
    }
    #[test]
    fn unregister_account_removes_owned_nfts_and_asset_metadata() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("cleanup", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let other_domain_id: DomainId = DomainId::try_new("other", "world").expect("domain id");
        seed_domain(&mut state, &other_domain_id, &authority);
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        let asset_def_id: AssetDefinitionId =
            AssetDefinitionId::derive_from_components(domain_id.clone(), "rose".parse().unwrap());
        Register::asset_definition({
            let __asset_definition_id = asset_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&authority, &mut tx)
        .expect("register asset definition");
        let asset_id = AssetId::new(asset_def_id.clone(), account_id.clone());
        let quantity = Quantity::from(5_u32);
        let asset = Asset::new(asset_id.clone(), quantity.clone());
        let (asset_id, asset_value) = asset.into_key_value();
        tx.world.assets.insert(asset_id.clone(), asset_value);
        tx.world.track_asset_holder(&asset_id);
        tx.world
            .increase_asset_total_amount(&asset_def_id, &quantity)
            .expect("fixture asset total must match the inserted balance");
        let key: Name = "tag".parse().unwrap();
        let value = Json::from(norito::json!("owned"));
        let mut metadata = Metadata::default();
        metadata.insert(key, value);
        tx.world.asset_metadata.insert(asset_id.clone(), metadata);
        let nft_id = NftId::new(other_domain_id.clone(), "dragon".parse().unwrap());
        let nft = Nft {
            id: nft_id.clone(),
            content: Metadata::default(),
            owned_by: account_id.clone(),
        };
        let (nft_id, nft_value) = nft.into_key_value();
        tx.world.insert_nft_entry(nft_id.clone(), nft_value);
        tx.nexus.fees.fee_sink_account_id = authority.clone();
        tx.nexus.staking.stake_escrow_account_id = authority.to_string();
        tx.nexus.staking.slash_sink_account_id = authority.to_string();
        Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister account");
        assert!(
            tx.world.assets.get(&asset_id).is_none(),
            "asset should be removed"
        );
        assert!(
            tx.world.asset_metadata.get(&asset_id).is_none(),
            "asset metadata should be removed with asset"
        );
        assert!(
            tx.world.nfts.get(&nft_id).is_none(),
            "owned NFT should be removed"
        );
    }
    #[test]
    fn unregister_account_removes_foreign_nft_permissions_from_accounts_and_roles() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("cleanup", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let foreign_domain_id: DomainId = DomainId::try_new("foreign", "world").expect("domain id");
        seed_domain(&mut state, &foreign_domain_id, &authority);
        let holder_domain: DomainId = DomainId::try_new("holders", "world").expect("domain id");
        seed_domain(&mut state, &holder_domain, &authority);
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let holder_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register target account");
        Register::account(NewAccount::new(holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register holder account");
        let nft_id = NftId::new(foreign_domain_id, "dragon".parse().unwrap());
        let nft = Nft {
            id: nft_id.clone(),
            content: Metadata::default(),
            owned_by: account_id.clone(),
        };
        let (nft_id, nft_value) = nft.into_key_value();
        tx.world.insert_nft_entry(nft_id.clone(), nft_value);
        let permission: Permission = iroha_executor_data_model::permission::nft::CanTransferNft {
            nft: nft_id.clone(),
        }
        .into();
        Grant::account_permission(permission.clone(), holder_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant permission to holder");
        let role_id: RoleId = "NFT_CLEANUP".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register role");
        Grant::role_permission(permission.clone(), role_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant permission to role");
        assert!(
            tx.world
                .account_permissions
                .get(&holder_id)
                .is_some_and(|perms| perms.contains(&permission)),
            "holder should have permission before unregister"
        );
        let role = tx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            role.permissions().any(|perm| perm == &permission),
            "role should include permission before unregister"
        );
        Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister account");
        assert!(
            tx.world.nfts.get(&nft_id).is_none(),
            "foreign-domain NFT owned by removed account should be removed"
        );
        assert!(
            !tx.world
                .account_permissions
                .get(&holder_id)
                .is_some_and(|perms| perms.contains(&permission)),
            "holder permission should be removed"
        );
        let role = tx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            !role.permissions().any(|perm| perm == &permission),
            "role permission should be removed"
        );
        assert!(
            !role.permission_epochs().contains_key(&permission),
            "permission epochs should be pruned"
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_owns_domain() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("owner", "world").expect("domain id");
        let external_domain: DomainId = DomainId::try_new("external", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        seed_domain(&mut state, &external_domain, &account_id);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        let err = Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect_err("account owning a domain must not be unregistered");
        let err_string = err.to_string();
        assert!(
            err_string.contains("owns domain"),
            "error should explain ownership conflict: {err_string}"
        );
        assert!(
            tx.world.accounts.get(&account_id).is_some(),
            "account should remain after rejected unregister"
        );
    }
    #[test]
    fn unregister_account_rejects_immutable_governance_lock_custody_after_config_change() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let custody_account = AccountId::new(checked_keypair().public_key().clone());
        let owner = (*BOB_ID).clone();
        state.gov.bond_escrow_account = authority.clone();
        state.gov.slash_receiver_account = authority.clone();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(custody_account.clone()))
            .execute(&authority, &mut tx)
            .expect("register retained custody account");
        let mut locks = GovernanceLocksForReferendum::default();
        locks.locks.insert(
            owner.clone(),
            GovernanceLockRecord {
                owner,
                amount: Quantity::from(150_u32),
                slashed: Quantity::zero(),
                expiry_height: 10,
                direction: 0,
                duration_blocks: 3_600,
                custody: GovernanceLockCustody {
                    escrowed: true,
                    asset_definition_id: tx.gov.voting_asset_id.clone(),
                    bond_escrow_account: custody_account.clone(),
                    slash_receiver_account: custody_account.clone(),
                },
            },
        );
        tx.world
            .put_governance_locks("retained-account-custody".to_owned(), locks);
        let err = Unregister::account(custody_account.clone())
            .execute(&authority, &mut tx)
            .expect_err("immutable lock custody account must remain registered");
        assert!(
            err.to_string()
                .contains("retained by immutable governance lock custody"),
            "error should identify retained lock custody: {err}"
        );
        assert!(
            tx.world.accounts.get(&custody_account).is_some(),
            "custody account must remain after rejected unregister"
        );
    }
    #[test]
    fn unregister_account_removes_account_read_permissions_from_accounts_and_roles() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("cleanup", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let holder_domain: DomainId = DomainId::try_new("holders", "world").expect("domain id");
        seed_domain(&mut state, &holder_domain, &authority);
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let holder_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register target account");
        Register::account(NewAccount::new(holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register holder account");
        let permission: Permission =
            iroha_executor_data_model::permission::query::CanReadAccountData {
                account: account_id.clone(),
            }
            .into();
        assert!(
            iroha_executor_data_model::permission::query::CanReadAccountData::try_from(&permission)
                .is_ok(),
            "permission should decode as CanReadAccountData"
        );
        Grant::account_permission(permission.clone(), holder_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant permission to holder");
        let role_id: RoleId = "ACCOUNT_CLEANUP".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register role");
        Grant::role_permission(permission.clone(), role_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant permission to role");
        assert!(
            tx.world
                .account_permissions
                .get(&holder_id)
                .is_some_and(|perms| perms.contains(&permission)),
            "holder should have permission before unregister"
        );
        let role = tx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            role.permissions().any(|perm| perm == &permission),
            "role should include permission before unregister"
        );
        Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister account");
        assert!(
            !tx.world
                .account_permissions
                .get(&holder_id)
                .is_some_and(|perms| perms.contains(&permission)),
            "holder permission should be removed"
        );
        let role = tx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            !role.permissions().any(|perm| perm == &permission),
            "role permission should be removed"
        );
        assert!(
            !role.permission_epochs().contains_key(&permission),
            "permission epochs should be pruned"
        );
    }
    #[test]
    fn unregister_account_removes_permissions_for_deleted_account() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("cleanup", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let retained_domain: DomainId = DomainId::try_new("retained", "world").expect("domain id");
        seed_domain(&mut state, &retained_domain, &authority);
        let holder_domain: DomainId = DomainId::try_new("holders", "world").expect("domain id");
        seed_domain(&mut state, &holder_domain, &authority);
        let keypair = checked_keypair();
        let target_id = AccountId::new(keypair.public_key().clone());
        let holder_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(target_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register target account");
        Register::account(NewAccount::new(holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register holder account");
        let permission: Permission =
            iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                account: target_id.clone(),
            }
            .into();
        Grant::account_permission(permission.clone(), holder_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant permission to holder");
        let role_id: RoleId = "CROSS_DOMAIN_PRESERVE".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register role");
        Grant::role_permission(permission.clone(), role_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant permission to role");
        Unregister::account(target_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister target account");
        assert!(
            !tx.world
                .account_permissions
                .get(&holder_id)
                .is_some_and(|perms| perms.contains(&permission)),
            "holder permission for removed subject should be pruned"
        );
        let role = tx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            !role.permissions().any(|perm| perm == &permission),
            "role permission for removed subject should be pruned"
        );
        assert!(
            !role.permission_epochs().contains_key(&permission),
            "permission epoch should be pruned for removed subject"
        );
    }
    fn with_registered_account_unregistration_candidate(
        test: impl FnOnce(AccountId, DomainId, AccountId, &mut crate::state::StateTransaction<'_, '_>),
    ) {
        let mut state = test_state();
        let domain_id = DomainId::try_new("owner", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut transaction)
            .expect("register account");
        test(authority, domain_id, account_id, &mut transaction);
    }
    fn with_registered_asset_definition_unregistration_candidate(
        test: impl FnOnce(AccountId, AssetDefinitionId, &mut crate::state::StateTransaction<'_, '_>),
    ) {
        with_registered_asset_definition_unregistration_candidate_with_policy(|_, _| {}, test);
    }
    fn with_registered_asset_definition_unregistration_candidate_with_policy(
        configure_policy: impl FnOnce(&mut State, &AssetDefinitionId),
        test: impl FnOnce(AccountId, AssetDefinitionId, &mut crate::state::StateTransaction<'_, '_>),
    ) {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let asset_domain = DomainId::try_new("asset", "guard").expect("asset domain id");
        seed_domain(&mut state, &asset_domain, &authority);
        let asset_definition_id =
            AssetDefinitionId::derive_from_components(asset_domain, "usd".parse().unwrap());
        configure_policy(&mut state, &asset_definition_id);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::asset_definition({
            let asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                asset_definition_id,
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&authority, &mut transaction)
        .expect("register asset definition");
        test(authority, asset_definition_id, &mut transaction);
    }
    #[test]
    fn unregister_account_rejects_when_account_owns_asset_definition() {
        with_registered_account_unregistration_candidate(|authority, domain_id, account_id, tx| {
            let asset_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
                domain_id.clone(),
                "bond".parse().unwrap(),
            );
            Register::asset_definition({
                let __asset_definition_id = asset_def_id.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "bond".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .execute(&authority, tx)
            .expect("register asset definition");
            tx.world
                .asset_definition_mut(&asset_def_id)
                .expect("definition exists")
                .set_owned_by(account_id.clone());
            tx.world
                .replace_asset_definition_owner_index(&asset_def_id, &authority, &account_id);
            let err = Unregister::account(account_id.clone())
                .execute(&authority, tx)
                .expect_err("account owning an asset definition must not be unregistered");
            let err_string = err.to_string();
            assert!(
                err_string.contains("owns asset definition"),
                "error should explain ownership conflict: {err_string}"
            );
            assert!(
                tx.world.accounts.get(&account_id).is_some(),
                "account should remain after rejected unregister"
            );
        });
    }
    #[test]
    fn unregister_account_rejects_active_and_inactive_retained_contract_subjects() {
        for (nonce, active) in [(31_u64, false), (32_u64, true)] {
            let state = test_state();
            let authority = (*ALICE_ID).clone();
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut tx = block.transaction();
            let contract =
                ContractAddress::derive(tx.network_id(), &authority, nonce, DataSpaceId::UNIVERSAL)
                    .expect("contract address");
            tx.world.bind_inactive_contract_subject_for_testing(
                contract.clone(),
                contract.subject_id(),
            );
            let subject = contract.subject_id();
            if active {
                let code_hash = Hash::new(b"retained-contract-subject-unregister");
                tx.world
                    .contract_instances
                    .insert(contract.clone(), code_hash);
                tx.world
                    .contract_subject_bindings
                    .get_mut(&contract)
                    .expect("retained contract binding")
                    .lifecycle
                    .active_code_hash = Some(code_hash);
                tx.world
                    .contract_subject_bindings
                    .get_mut(&contract)
                    .unwrap()
                    .lifecycle
                    .retained_code_hash = Some(code_hash);
            }

            let error = Unregister::account(subject.clone())
                .execute(&authority, &mut tx)
                .expect_err("retained contract subject must never be unregistered");
            assert!(
                error
                    .to_string()
                    .contains(&format!("retained subject of contract `{contract}`")),
                "error must identify the exact retained contract: {error}"
            );
            assert!(
                tx.world.accounts.get(&subject).is_some(),
                "rejected {active:?} contract-subject removal must preserve the account"
            );
        }
    }
    #[test]
    fn unregister_account_rejects_contract_owner_and_pending_recipient_until_cleared() {
        with_registered_account_unregistration_candidate(|authority, _, account_id, tx| {
            let contract =
                ContractAddress::derive(tx.network_id(), &authority, 17, DataSpaceId::UNIVERSAL)
                    .expect("contract address");
            let subject = contract.subject_id();
            Register::account(NewAccount::new(subject.clone()))
                .execute(&authority, tx)
                .expect("register contract subject");
            let mut binding = crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &contract,
                authority.clone(),
            );
            binding.lifecycle.owner =
                iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Account(
                    account_id.clone(),
                );
            tx.world
                .contract_subject_bindings
                .insert(contract.clone(), binding);
            tx.world
                .contract_subject_addresses
                .insert(subject, contract.clone());

            let owned = Unregister::account(account_id.clone())
                .execute(&authority, tx)
                .expect_err("current contract owner must not be unregistered");
            assert!(
                owned.to_string().contains(&format!(
                    "transfer or cancel its lifecycle ownership of contract `{contract}` first"
                )),
                "error should identify the retained owned contract: {owned}"
            );
            assert!(tx.world.accounts.get(&account_id).is_some());

            let lifecycle = &mut tx
                .world
                .contract_subject_bindings
                .get_mut(&contract)
                .expect("contract lifecycle binding")
                .lifecycle;
            lifecycle.owner =
                iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Parliament;
            lifecycle.pending_owner = Some(
                iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Account(
                    account_id.clone(),
                ),
            );
            lifecycle.revision += 1;

            let pending = Unregister::account(account_id.clone())
                .execute(&authority, tx)
                .expect_err("pending contract owner must not be unregistered");
            assert!(
                pending.to_string().contains(&format!(
                    "transfer or cancel its lifecycle ownership of contract `{contract}` first"
                )),
                "error should identify the retained pending contract: {pending}"
            );
            assert!(tx.world.accounts.get(&account_id).is_some());

            let lifecycle = &mut tx
                .world
                .contract_subject_bindings
                .get_mut(&contract)
                .expect("contract lifecycle binding")
                .lifecycle;
            lifecycle.pending_owner = None;
            lifecycle.revision += 1;
            Unregister::account(account_id.clone())
                .execute(&authority, tx)
                .expect("account removal succeeds after lifecycle references are cleared");
            assert!(tx.world.accounts.get(&account_id).is_none());
        });
    }
    #[test]
    fn unregister_account_rejects_when_account_has_contract_deployment_nonce_state() {
        let mut state = test_state();
        let domain_id: DomainId =
            DomainId::try_new("contract_deployer", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        let nonce_key: Name = iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY
            .parse()
            .expect("contract deployment nonce key");
        tx.world
            .account_mut(&account_id)
            .expect("registered account")
            .insert(nonce_key.clone(), Json::new(1_u64));
        let err = Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect_err("contract deployer identity must retain its monotonic nonce state");
        let err_string = err.to_string();
        assert!(
            err_string.contains("contract deployment nonce state")
                && err_string.contains("address monotonicity"),
            "error should explain the deployment replay invariant: {err_string}"
        );
        assert!(
            tx.world.accounts.get(&account_id).is_some(),
            "account and nonce must remain after rejected unregister"
        );
        assert_eq!(
            tx.world
                .account(&account_id)
                .expect("account remains")
                .metadata()
                .get(&nonce_key),
            Some(&Json::new(1_u64)),
            "deployment nonce must remain unchanged"
        );
    }
    fn assert_account_unregister_guard(
        configure: impl FnOnce(
            &mut crate::state::StateTransaction<'_, '_>,
            &DomainId,
            &AccountId,
            &AccountId,
        ),
        reject_message: &str,
        error_fragment: &str,
        error_diagnostic: &str,
    ) {
        assert_account_unregister_guard_with_policy(
            |_, _| {},
            configure,
            reject_message,
            error_fragment,
            error_diagnostic,
        );
    }
    fn assert_account_unregister_guard_with_policy(
        configure_policy: impl FnOnce(&mut State, &AccountId),
        configure: impl FnOnce(
            &mut crate::state::StateTransaction<'_, '_>,
            &DomainId,
            &AccountId,
            &AccountId,
        ),
        reject_message: &str,
        error_fragment: &str,
        error_diagnostic: &str,
    ) {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("owner", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        configure_policy(&mut state, &account_id);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        configure(&mut tx, &domain_id, &authority, &account_id);
        let err = Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect_err(reject_message);
        let err_string = err.to_string();
        assert!(
            err_string.contains(error_fragment),
            "{error_diagnostic}: {err_string}"
        );
        assert!(
            tx.world.accounts.get(&account_id).is_some(),
            "account should remain after rejected unregister"
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_governance_bond_escrow_account() {
        assert_account_unregister_guard_with_policy(
            |state, account_id| {
                state.gov.bond_escrow_account = account_id.clone();
            },
            |_, _, _, _| {},
            "governance bond escrow account must not be unregistered",
            "governance bond escrow account",
            "error should explain governance bond escrow conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_governance_viral_incentive_pool_account() {
        assert_account_unregister_guard_with_policy(
            |state, account_id| {
                state.gov.viral_incentives.incentive_pool_account = account_id.clone();
            },
            |_, _, _, _| {},
            "governance viral incentive pool account must not be unregistered",
            "governance viral incentive pool account",
            "error should explain governance viral incentive pool conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_oracle_reward_pool() {
        assert_account_unregister_guard_with_policy(
            |state, account_id| {
                state.oracle.economics.reward_pool = account_id.clone();
            },
            |_, _, _, _| {},
            "oracle reward pool account must not be unregistered",
            "oracle reward pool account",
            "error should explain oracle reward-pool conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_nexus_fee_sink_account() {
        assert_account_unregister_guard(
            |tx, _domain_id, authority, account_id| {
                let helper_account_id = AccountId::new(checked_keypair().public_key().clone());
                Register::account(NewAccount::new(helper_account_id.clone()))
                    .execute(authority, tx)
                    .expect("register helper account");
                tx.nexus.fees.fee_sink_account_id = account_id.clone();
                tx.nexus.staking.stake_escrow_account_id = helper_account_id.to_string();
                tx.nexus.staking.slash_sink_account_id = helper_account_id.to_string();
            },
            "committed root fee sink account must not be unregistered",
            "committed root fee sink; commit a replacement root fee policy first",
            "error should explain nexus fee-sink conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_nexus_fee_sink_account_is_configured() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let sink_domain: DomainId = DomainId::try_new("sink", "world").expect("domain id");
        let remove_domain: DomainId = DomainId::try_new("remove", "world").expect("domain id");
        seed_domain(&mut state, &sink_domain, &authority);
        seed_domain(&mut state, &remove_domain, &authority);
        let account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register configured account");
        tx.nexus.fees.fee_sink_account_id = account_id.clone();
        tx.nexus.staking.stake_escrow_account_id = account_id.to_string();
        tx.nexus.staking.slash_sink_account_id = account_id.to_string();
        let err = Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect_err("configured account must remain protected");
        let err_string = err.to_string();
        assert!(
            err_string
                .contains("committed root fee sink; commit a replacement root fee policy first"),
            "error should explain nexus fee-sink conflict: {err_string}"
        );
        assert!(
            tx.world.accounts.get(&account_id).is_some(),
            "configured sink account should remain"
        );
    }
    #[test]
    fn unregister_account_allows_unrelated_account_when_fee_sink_is_different_account() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let remove_domain: DomainId = DomainId::try_new("remove", "world").expect("domain id");
        let sink_domain: DomainId = DomainId::try_new("sink", "world").expect("domain id");
        seed_domain(&mut state, &remove_domain, &authority);
        seed_domain(&mut state, &sink_domain, &authority);
        let remove_account_id = AccountId::new(checked_keypair().public_key().clone());
        let sink_account_id = AccountId::new(checked_keypair().public_key().clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(sink_account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register sink account");
        Register::account(NewAccount::new(remove_account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register removal candidate account");
        tx.nexus.fees.fee_sink_account_id = sink_account_id.clone();
        Unregister::account(remove_account_id.clone())
            .execute(&authority, &mut tx)
            .expect("unrelated account should not be blocked by the configured sink account");
        assert!(
            tx.world.accounts.get(&remove_account_id).is_none(),
            "removal candidate should be deleted"
        );
        assert!(
            tx.world.accounts.get(&sink_account_id).is_some(),
            "configured sink account should remain"
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_nexus_staking_escrow_account() {
        assert_account_unregister_guard(
            |tx, _domain_id, authority, account_id| {
                let helper_account_id = AccountId::new(checked_keypair().public_key().clone());
                Register::account(NewAccount::new(helper_account_id.clone()))
                    .execute(authority, tx)
                    .expect("register helper account");
                tx.nexus.fees.fee_sink_account_id = helper_account_id.clone();
                tx.nexus.staking.stake_escrow_account_id = account_id.to_string();
                tx.nexus.staking.slash_sink_account_id = helper_account_id.to_string();
            },
            "nexus staking escrow account must not be unregistered",
            "nexus staking escrow account",
            "error should explain nexus staking-escrow conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_nexus_staking_slash_sink_account() {
        assert_account_unregister_guard(
            |tx, _domain_id, authority, account_id| {
                let helper_account_id = AccountId::new(checked_keypair().public_key().clone());
                Register::account(NewAccount::new(helper_account_id.clone()))
                    .execute(authority, tx)
                    .expect("register helper account");
                tx.nexus.fees.fee_sink_account_id = helper_account_id.clone();
                tx.nexus.staking.stake_escrow_account_id = helper_account_id.to_string();
                tx.nexus.staking.slash_sink_account_id = account_id.to_string();
            },
            "nexus staking slash sink account must not be unregistered",
            "nexus staking slash sink account",
            "error should explain nexus staking slash-sink conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_content_publish_allow_account() {
        assert_account_unregister_guard_with_policy(
            |state, account_id| {
                state.content.publish_allow_accounts = vec![account_id.clone()];
            },
            |_, _, _, _| {},
            "content publish allow-list account must not be unregistered",
            "content publish allow-list account",
            "error should explain content publish-allow conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_sorafs_telemetry_submitter() {
        assert_account_unregister_guard_with_policy(
            |state, account_id| {
                state.gov.sorafs_telemetry.submitters = vec![account_id.clone()];
            },
            |_, _, _, _| {},
            "SoraFS telemetry submitter account must not be unregistered",
            "SoraFS telemetry submitter",
            "error should explain telemetry-submitter conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_is_configured_sorafs_provider_owner() {
        assert_account_unregister_guard_with_policy(
            |state, account_id| {
                let provider_id = iroha_data_model::sorafs::capacity::ProviderId::new([0xD4; 32]);
                state
                    .gov
                    .sorafs_provider_owners
                    .insert(provider_id, account_id.clone());
            },
            |_, _, _, _| {},
            "configured SoraFS provider-owner account must not be unregistered",
            "configured as SoraFS provider owner",
            "error should explain configured provider-owner conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_owns_sorafs_provider() {
        with_registered_account_unregistration_candidate(
            |authority, _domain_id, account_id, tx| {
                let provider_id = iroha_data_model::sorafs::capacity::ProviderId::new([0xB1; 32]);
                tx.world
                    .provider_owners
                    .insert(provider_id, account_id.clone());
                let err = Unregister::account(account_id.clone())
                    .execute(&authority, tx)
                    .expect_err("account owning a provider must not be unregistered");
                let err_string = err.to_string();
                assert!(
                    err_string.contains("owns SoraFS provider"),
                    "error should explain ownership conflict: {err_string}"
                );
                assert!(
                    tx.world.accounts.get(&account_id).is_some(),
                    "account should remain after rejected unregister"
                );
            },
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_citizenship_record() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                tx.world.citizens.insert(
                    account_id.clone(),
                    crate::state::CitizenshipRecord::new(account_id.clone(), 100_u64.into(), 1),
                );
            },
            "account with citizenship record must not be unregistered",
            "active citizenship record",
            "error should explain citizenship conflict",
        );
    }
    #[test]
    fn unregister_account_preserves_pinned_staking_custody_after_config_change() {
        with_registered_account_unregistration_candidate(|authority, domain_id, account_id, tx| {
            tx.nexus.staking.stake_escrow_account_id = authority.to_string();
            let asset = AssetId::new(
                AssetDefinitionId::derive_from_components(domain_id, "stake".parse().unwrap()),
                account_id.clone(),
            );
            let key = (LaneId::SINGLE, authority.clone());
            tx.world
                .public_lane_stake_custody
                .insert(key.clone(), (asset.clone(), Quantity::one()));
            for has_custody_row in [true, false] {
                let reserves_before = tx.world.public_lane_stake_reserves.get(&asset).cloned();
                let error = Unregister::account(account_id.clone())
                    .execute(&authority, tx)
                    .expect_err("pinned escrow owner must remain registered");
                assert!(
                    error
                        .to_string()
                        .contains("pinned public-lane staking custody"),
                    "{error}"
                );
                assert!(tx.world.accounts.get(&account_id).is_some());
                assert_eq!(
                    tx.world.public_lane_stake_reserves.get(&asset),
                    reserves_before.as_ref()
                );
                if has_custody_row {
                    tx.world.public_lane_stake_custody.remove(key.clone());
                    tx.world
                        .public_lane_stake_reserves
                        .insert(asset.clone(), Quantity::one());
                }
            }
            tx.world.public_lane_stake_reserves.remove(asset);
            Unregister::account(account_id.clone())
                .execute(&authority, tx)
                .expect("former escrow owner can be removed after liability release");
            assert!(tx.world.accounts.get(&account_id).is_none());
        });
    }
    #[test]
    fn unregister_account_rejects_when_account_has_public_lane_validator_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                tx.world.public_lane_validators.insert(
                    (LaneId::SINGLE, account_id.clone()),
                    iroha_data_model::nexus::PublicLaneValidatorRecord {
                        lane_id: LaneId::SINGLE,
                        validator: account_id.clone(),
                        peer_id: PeerId::from(account_id.expect_single_signatory().clone()),
                        stake_account: account_id.clone(),
                        total_stake: Quantity::from(1_u32),
                        self_stake: Quantity::from(1_u32),
                        metadata: Metadata::default(),
                        status: iroha_data_model::nexus::PublicLaneValidatorStatus::Active,
                        activation_height: 1,
                        election_exit_height: None,
                        deactivation_height: None,
                    },
                );
            },
            "account with validator stake state must not be unregistered",
            "public-lane validator stake state",
            "error should explain staking conflict",
        );
    }
    #[test]
    fn unregister_account_ignores_mismatched_public_lane_validator_row() {
        with_registered_account_unregistration_candidate(
            |authority, _domain_id, account_id, tx| {
                tx.world.public_lane_validators.insert(
                    (LaneId::SINGLE, account_id.clone()),
                    iroha_data_model::nexus::PublicLaneValidatorRecord {
                        lane_id: LaneId::new(1),
                        validator: account_id.clone(),
                        peer_id: PeerId::from(account_id.expect_single_signatory().clone()),
                        stake_account: account_id.clone(),
                        total_stake: Quantity::from(1_u32),
                        self_stake: Quantity::from(1_u32),
                        metadata: Metadata::default(),
                        status: iroha_data_model::nexus::PublicLaneValidatorStatus::Active,
                        activation_height: 1,
                        election_exit_height: None,
                        deactivation_height: None,
                    },
                );
                Unregister::account(account_id.clone())
                    .execute(&authority, tx)
                    .expect("mismatched validator row must not block account unregister");
                assert!(
                    tx.world.accounts.get(&account_id).is_none(),
                    "account should be unregistered when only malformed validator state references it"
                );
                let record = tx
                    .world
                    .public_lane_validators
                    .get(&(LaneId::SINGLE, account_id))
                    .expect("malformed validator row remains as stored");
                assert_eq!(record.lane_id, LaneId::new(1));
                assert!(matches!(
                    record.status,
                    iroha_data_model::nexus::PublicLaneValidatorStatus::Active
                ));
            },
        );
    }

    #[test]
    fn unregister_account_ignores_mismatched_public_lane_economic_rows() {
        with_registered_account_unregistration_candidate(
            |authority, _domain_id, account_id, tx| {
                tx.world.public_lane_stake_shares.insert(
                    (LaneId::SINGLE, account_id.clone(), authority.clone()),
                    iroha_data_model::nexus::PublicLaneStakeShare {
                        lane_id: LaneId::new(1),
                        validator: account_id.clone(),
                        staker: authority.clone(),
                        bonded: Quantity::from(1_u32),
                        pending_unbonds: std::collections::BTreeMap::new(),
                        metadata: Metadata::default(),
                    },
                );
                Unregister::account(account_id.clone())
                    .execute(&authority, tx)
                    .expect(
                        "mismatched public-lane economic rows must not block account unregister",
                    );
                assert!(
                    tx.world.accounts.get(&account_id).is_none(),
                    "account should be unregistered when only malformed economic rows reference it"
                );
                assert!(
                    tx.world
                        .public_lane_stake_shares
                        .get(&(LaneId::SINGLE, account_id.clone(), authority))
                        .is_some(),
                    "malformed stake-share row remains as stored"
                );
            },
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_repo_agreement_state() {
        assert_account_unregister_guard(
            |tx, domain_id, authority, account_id| {
                let repo_id: iroha_data_model::repo::RepoAgreementId =
                    "repoguard".parse().expect("repo agreement id");
                let agreement = iroha_data_model::repo::RepoAgreement::new(
                    repo_id.clone(),
                    account_id.clone(),
                    authority.clone(),
                    iroha_data_model::repo::RepoCashLeg {
                        asset_definition_id: AssetDefinitionId::derive_from_components(
                            domain_id.clone(),
                            "usd".parse().unwrap(),
                        ),
                        quantity: Quantity::from(10_u32),
                    },
                    AssetId::new(
                        AssetDefinitionId::derive_from_components(
                            domain_id.clone(),
                            "usd".parse().unwrap(),
                        ),
                        authority.clone(),
                    ),
                    iroha_data_model::repo::RepoCollateralLeg::new(
                        AssetDefinitionId::derive_from_components(
                            domain_id.clone(),
                            "bond".parse().unwrap(),
                        ),
                        Quantity::from(12_u32),
                    ),
                    AssetId::new(
                        AssetDefinitionId::derive_from_components(
                            domain_id.clone(),
                            "bond".parse().unwrap(),
                        ),
                        authority.clone(),
                    ),
                    250,
                    1000,
                    1,
                    iroha_data_model::repo::RepoGovernance::new(1_000, 60, false),
                    None,
                );
                tx.world.insert_repo_agreement_entry(agreement);
            },
            "account with repo agreement state must not be unregistered",
            "repo agreement state",
            "error should explain repo-state conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_committed_settlement_receipt() {
        assert_account_unregister_guard(
            |tx, domain_id, authority, account_id| {
                let settlement_id: iroha_data_model::isi::SettlementId =
                    iroha_data_model::isi::SettlementId::new(
                        account_id.clone(),
                        "settleguard".parse().expect("settlement reference"),
                    );
                let receipt = iroha_data_model::isi::SettlementReceipt {
                    authority: account_id.clone(),
                    metadata: Metadata::default(),
                    block_height: 1,
                    block_hash: iroha_crypto::HashOf::<
                        iroha_data_model::block::BlockHeader,
                    >::from_untyped_unchecked(Hash::prehashed([0; Hash::LENGTH])),
                    executed_at_ms: 1,
                    details: iroha_data_model::isi::SettlementDetails::Dvp(iroha_data_model::isi::DvpSettlementDetails { delivery: { let leg = iroha_data_model::isi::SettlementLeg::new(
                                AssetDefinitionId::derive_from_components(
                                    domain_id.clone(),
                                    "usd".parse().unwrap(),
                                ),
                                Quantity::one(),
                                account_id.clone(),
                                authority.clone(),
                            ); iroha_data_model::isi::ResolvedSettlementMovement {
                source: AssetId::with_scope(leg.asset_definition_id().clone(), leg.from().clone(), iroha_data_model::asset::AssetBalanceScope::Global),
                destination: AssetId::with_scope(leg.asset_definition_id().clone(), leg.to().clone(), iroha_data_model::asset::AssetBalanceScope::Global),
                quantity: leg.quantity().clone(), metadata: leg.metadata().clone(),
            } }, payment: { let leg = iroha_data_model::isi::SettlementLeg::new(
                                AssetDefinitionId::derive_from_components(
                                    domain_id.clone(),
                                    "eur".parse().unwrap(),
                                ),
                                Quantity::one(),
                                authority.clone(),
                                account_id.clone(),
                            ); iroha_data_model::isi::ResolvedSettlementMovement {
                source: AssetId::with_scope(leg.asset_definition_id().clone(), leg.from().clone(), iroha_data_model::asset::AssetBalanceScope::Global),
                destination: AssetId::with_scope(leg.asset_definition_id().clone(), leg.to().clone(), iroha_data_model::asset::AssetBalanceScope::Global),
                quantity: leg.quantity().clone(), metadata: leg.metadata().clone(),
            } }, order: iroha_data_model::isi::SettlementExecutionOrder::DeliveryThenPayment }),
                };
                let consent = Permission::from(
                    iroha_executor_data_model::permission::settlement::CanExecuteSettlement {
                        debited_asset: receipt
                            .details
                            .movements()
                            .nth(1)
                            .expect("payment leg")
                            .source
                            .clone(),
                        settlement_id: settlement_id.clone(),
                        intent_hash: Hash::new(b"retained-owner-scoped-consent"),
                    },
                );
                tx.world.account_permissions.insert(
                    authority.clone(),
                    std::collections::BTreeSet::from([consent.clone()]),
                );
                tx.world.settlement_receipts.insert(settlement_id, receipt);
                Unregister::account(account_id.clone())
                    .execute(authority, tx)
                    .expect_err("receipt must prevent removing the identity owner");
                assert!(
                    tx.world
                        .account_permissions
                        .get(authority)
                        .expect("retained permissions")
                        .contains(&consent),
                    "refused unregister must preserve the owner-scoped counterparty consent"
                );
            },
            "account with a committed settlement receipt must not be unregistered",
            "committed settlement receipt",
            "error should explain settlement-state conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_oracle_feed_provider_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                let mut feed = iroha_data_model::oracle::kits::price_xor_usd().feed_config;
                feed.providers = vec![account_id.clone()];
                tx.world.oracle_feeds.insert(feed.feed_id.clone(), feed);
            },
            "account with oracle provider state must not be unregistered",
            "active oracle feed provider state",
            "error should explain oracle-state conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_oracle_feed_history_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                let kit = iroha_data_model::oracle::kits::price_xor_usd();
                let feed = kit.feed_config;
                let feed_id = feed.feed_id.clone();
                let request_hash = kit.connector_request.request_hash();
                tx.world.oracle_history.insert(
                    feed_id.clone(),
                    vec![iroha_data_model::events::data::oracle::FeedEventRecord {
                        event: iroha_data_model::oracle::FeedEvent {
                            feed_id: feed_id.clone(),
                            feed_config_version: feed.feed_config_version,
                            slot: 1,
                            request_hash,
                            outcome: iroha_data_model::oracle::FeedEventOutcome::Success(
                                iroha_data_model::oracle::FeedSuccess {
                                    value: iroha_data_model::oracle::ObservationValue::new(
                                        1_000, 2,
                                    ),
                                    entries: vec![iroha_data_model::oracle::ReportEntry {
                                        oracle_id: account_id.clone(),
                                        observation_hash:
                                            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                                                b"oracle-history-account-guard",
                                            )),
                                        value: iroha_data_model::oracle::ObservationValue::new(
                                            1_000, 2,
                                        ),
                                        outlier: false,
                                    }],
                                },
                            ),
                        },
                        recorded_at_ms: 1,
                        evidence_hashes: Vec::new(),
                    }],
                );
            },
            "account with oracle history state must not be unregistered",
            "active oracle feed history state",
            "error should explain oracle-history conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_governance_proposal_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                let proposal_id = [0xA5; 32];
                let kind = iroha_data_model::governance::types::ProposalKind::DeployContract(
                    iroha_data_model::governance::types::DeployContractProposal {
                        proposal_operator: account_id.clone(),
                        contract_address:
                            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                                .parse()
                                .expect("contract address"),
                        code_hash: iroha_data_model::governance::types::ContractCodeHash::new(
                            [0x11; 32],
                        ),
                        abi_hash: iroha_data_model::governance::types::ContractAbiHash::new(
                            [0x22; 32],
                        ),
                        abi_version: iroha_data_model::governance::types::AbiVersion::new(1),
                        manifest_provenance: None,
                    },
                );
                tx.world
                    .put_governance_proposal(
                        proposal_id,
                        crate::state::GovernanceProposalRecord {
                            proposer: account_id.clone(),
                            kind,
                            created_height: 1,
                            status: crate::state::GovernanceProposalStatus::Proposed,
                        },
                    )
                    .expect("domain test proposal must satisfy first-release JSON bounds");
            },
            "account with governance proposal state must not be unregistered",
            "active governance proposal state",
            "error should explain governance proposal conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_content_bundle_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                let bundle_id = Hash::new(b"content-bundle-account-guard");
                let stripe_layout = iroha_data_model::da::prelude::DaStripeLayout::default();
                let manifest = iroha_data_model::content::ContentBundleManifest {
                    bundle_id,
                    index_hash: [0x44; 32],
                    dataspace: DataSpaceId::UNIVERSAL,
                    lane: LaneId::SINGLE,
                    blob_class: iroha_data_model::da::types::BlobClass::GovernanceArtifact,
                    retention: iroha_data_model::da::types::RetentionPolicy::default(),
                    cache: iroha_data_model::content::ContentCachePolicy {
                        max_age_seconds: 60,
                        immutable: false,
                    },
                    auth: iroha_data_model::content::ContentAuthMode::Public,
                    stripe_layout,
                    mime_overrides: std::collections::BTreeMap::new(),
                };
                tx.world.content_bundles.insert(
                    bundle_id,
                    iroha_data_model::content::ContentBundleRecord {
                        bundle_id,
                        manifest,
                        total_bytes: 0,
                        chunk_size: 1,
                        chunk_hashes: Vec::new(),
                        chunk_root: [0; 32],
                        stripe_layout,
                        pdp_commitment: None,
                        files: Vec::new(),
                        created_by: account_id.clone(),
                        created_height: 1,
                        expires_at_height: None,
                    },
                );
            },
            "account with content bundle state must not be unregistered",
            "content bundle state",
            "error should explain content-bundle conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_runtime_upgrade_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
                    name: "runtime-guard".to_string(),
                    description: "guard".to_string(),
                    abi_version: 1,
                    abi_hash: [0x51; 32],
                    added_syscalls: Vec::new(),
                    added_pointer_types: Vec::new(),
                    start_height: 1,
                    end_height: 2,
                    sbom_digests: Vec::new(),
                    slsa_attestation: Vec::new(),
                    provenance: Vec::new(),
                };
                let upgrade_id = manifest.id();
                tx.world.runtime_upgrades.insert(
                    upgrade_id,
                    iroha_data_model::runtime::RuntimeUpgradeRecord {
                        manifest,
                        status: iroha_data_model::runtime::RuntimeUpgradeStatus::Proposed,
                        proposer: account_id.clone(),
                        created_height: 1,
                    },
                );
            },
            "account with runtime upgrade state must not be unregistered",
            "active runtime upgrade proposal state",
            "error should explain runtime-upgrade conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_viral_escrow_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                let binding_digest = Hash::new(b"viral-escrow-account-guard");
                tx.world.viral_escrows.insert(
                    binding_digest,
                    iroha_data_model::social::ViralEscrowRecord {
                        binding_hash: iroha_data_model::oracle::KeyedHash {
                            pepper_id: "pepper".to_string(),
                            digest: binding_digest,
                        },
                        sender: account_id.clone(),
                        amount: iroha_primitives::numeric::Quantity::from(1_u32),
                        created_at_ms: 1,
                    },
                );
            },
            "account with viral escrow state must not be unregistered",
            "active viral escrow state",
            "error should explain viral-escrow conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_sorafs_pin_manifest_state() {
        assert_account_unregister_guard(
            |tx, _domain_id, _authority, account_id| {
                let digest =
                    iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0xAB; 32]);
                tx.world.pin_manifests.insert(
                    digest,
                    iroha_data_model::sorafs::pin_registry::PinManifestRecord::new(
                        digest,
                        iroha_data_model::sorafs::pin_registry::ManifestRootCid::from_blake3_digest(
                            [0xBC; 32],
                        )
                        .expect("canonical manifest root CID"),
                        iroha_data_model::sorafs::pin_registry::ChunkerProfileHandle {
                            profile_id: 1,
                            namespace: "sorafs".to_string(),
                            name: "sf1".to_string(),
                            semver: "1.0.0".to_string(),
                            multihash_code: 0x1E,
                        },
                        [0xCD; 32],
                        [0; 32],
                        0,
                        iroha_data_model::sorafs::pin_registry::PinPolicy::default(),
                        account_id.clone(),
                        1,
                        None,
                        None,
                        Metadata::default(),
                    ),
                );
            },
            "account with SoraFS pin manifest state must not be unregistered",
            "active SoraFS pin manifest state",
            "error should explain SoraFS pin-manifest conflict",
        );
    }
    #[test]
    fn unregister_account_rejects_when_account_has_da_pin_intent_owner_state() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("owner", "world").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let network_id = *state.network_id_ref();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(account_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register account");
        let ticket_id = iroha_data_model::da::types::StorageTicketId::new([0xD1; 32]);
        let pin_authorization = crate::da::signed_test_ingest_authorization(
            network_id,
            &keypair,
            LaneId::new(1),
            1,
            1,
            1,
        );
        tx.world.da_pin_intents_by_ticket.insert(
            ticket_id,
            iroha_data_model::da::pin_intent::DaPinIntentWithLocation {
                intent: crate::da::signed_test_pin_intent(
                    pin_authorization,
                    &keypair,
                    ticket_id,
                    iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0xE2; 32]),
                    None,
                ),
                location: iroha_data_model::da::commitment::DaCommitmentLocation {
                    block_height: 1,
                    index_in_bundle: 0,
                },
            },
        );
        let err = Unregister::account(account_id.clone())
            .execute(&authority, &mut tx)
            .expect_err("account with DA pin intent owner state must not be unregistered");
        let err_string = err.to_string();
        assert!(
            err_string.contains("active DA pin intent owner state"),
            "error should explain DA pin intent owner conflict: {err_string}"
        );
        assert!(
            tx.world.accounts.get(&account_id).is_some(),
            "account should remain after rejected unregister"
        );
    }
    #[test]
    fn space_directory_events_drive_bindings() {
        let mut state = test_state();
        let domain_id: DomainId = DomainId::try_new("spaces", "events").expect("domain id");
        let authority = (*ALICE_ID).clone();
        seed_domain(&mut state, &domain_id, &authority);
        let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::events"));
        let dataspace = DataSpaceId::new(33);
        let manifest_hash = seed_manifest_record(&mut state.world, uaid, dataspace, |_| {});
        let keypair = checked_keypair();
        let account_id = AccountId::new(keypair.public_key().clone());
        let new_account = NewAccount::new(account_id.clone()).with_uaid(Some(uaid));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(new_account)
            .execute(&authority, &mut tx)
            .expect("register account");
        assert!(
            tx.world.uaid_dataspaces.get(&uaid).is_none(),
            "inactive manifest should not bind accounts"
        );
        tx.world
            .emit_events(Some(SpaceDirectoryEvent::ManifestActivated(
                SpaceDirectoryManifestActivated {
                    dataspace,
                    uaid,
                    manifest_hash,
                    activation_epoch: 10,
                    expiry_epoch: None,
                },
            )));
        let bindings = tx
            .world
            .uaid_dataspaces
            .get(&uaid)
            .expect("bindings must exist after activation");
        assert!(
            bindings
                .iter()
                .any(|(id, accounts)| *id == dataspace && accounts.contains(&account_id))
        );
        let manifest_record = tx
            .world
            .space_directory_manifests
            .get(&uaid)
            .and_then(|set| set.get(&dataspace))
            .expect("manifest record present");
        assert_eq!(
            manifest_record.lifecycle.activated_epoch,
            Some(10),
            "activation epoch recorded"
        );
        tx.world
            .emit_events(Some(SpaceDirectoryEvent::ManifestRevoked(
                SpaceDirectoryManifestRevoked {
                    dataspace,
                    uaid,
                    manifest_hash,
                    revoked_epoch: 25,
                    reason: Some("operator request".to_string()),
                },
            )));
        assert!(
            tx.world.uaid_dataspaces.get(&uaid).is_none(),
            "bindings cleared after revocation"
        );
        let manifest_record = tx
            .world
            .space_directory_manifests
            .get(&uaid)
            .and_then(|set| set.get(&dataspace))
            .expect("manifest record still present");
        assert!(
            manifest_record.lifecycle.revocation.is_some(),
            "revocation metadata recorded"
        );
        assert_eq!(
            manifest_record.lifecycle.revocation.as_ref().unwrap().epoch,
            25
        );
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    #[test]
    fn direct_dataspace_registration_checks_owner_route_and_balance_policy() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let dataspace =
            crate::sns::dataspace_id_for_sns_alias("paynet").expect("canonical SNS dataspace ID");
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut tx = block.transaction();
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: dataspace,
                alias: "paynet".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("catalog");
        tx.nexus.dataspace_catalog = catalog.clone();
        tx.world.dataspace_catalog = catalog;
        seed_dataspace_alias_lease(&mut tx, &authority, "paynet");
        tx.current_dataspace_id = Some(dataspace);
        tx.world.current_dataspace_id = Some(dataspace);
        tx.nexus.lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    dataspace_id: dataspace,
                    alias: "paynet".to_owned(),
                    visibility: LaneVisibility::Public,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("public lane");
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("fixture", "paynet").expect("synthetic identity seed"),
            "unit".parse().expect("name"),
        );
        let mut instruction = iroha_data_model::isi::RegisterDataspaceAssetDefinition::new(
            dataspace,
            AssetDefinition::numeric(
                id.clone(),
                "Unit".to_owned(),
                AssetBalancePolicy::DataspaceRestricted,
                None,
            ),
        )
        .expect("direct instruction");
        isi::ensure_dataspace_asset_definition_registration_allowed(
            &mut tx,
            &authority,
            &instruction,
        )
        .expect("exact current SNS owner and route");
        assert!(
            isi::ensure_dataspace_asset_definition_registration_allowed(
                &mut tx,
                &BOB_ID,
                &instruction
            )
            .is_err()
        );
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        assert!(
            isi::ensure_dataspace_asset_definition_registration_allowed(
                &mut tx,
                &authority,
                &instruction
            )
            .is_err()
        );
        tx.current_dataspace_id = Some(dataspace);
        let public_lanes = tx.nexus.lane_catalog.clone();
        tx.nexus.lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    dataspace_id: dataspace,
                    alias: "paynet".to_owned(),
                    visibility: LaneVisibility::Restricted,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("private lane");
        for policy in [
            AssetBalancePolicy::Global,
            AssetBalancePolicy::DataspaceRestricted,
        ] {
            instruction.object.balance_scope_policy = policy;
            let error = isi::ensure_dataspace_asset_definition_registration_allowed(
                &mut tx,
                &authority,
                &instruction,
            )
            .expect_err("a restricted home is refused under either balance policy");
            let expected = match policy {
                AssetBalancePolicy::Global => "cannot be registered in restricted dataspace",
                AssetBalancePolicy::DataspaceRestricted => "public home dataspace",
            };
            assert!(error.to_string().contains(expected), "{error}");
        }
        tx.nexus.lane_catalog = public_lanes;
        instruction.object.balance_scope_policy = AssetBalancePolicy::Global;
        isi::ensure_dataspace_asset_definition_registration_allowed(
            &mut tx,
            &authority,
            &instruction,
        )
        .expect("Global balances may have exact non-Universal public dataspace home");
        assert!(tx.world.asset_definitions.get(&id).is_none());
        assert!(
            tx.world
                .asset_definition_dataspace(&id)
                .expect("valid home registry")
                .is_none()
        );
    }
    #[test]
    fn direct_dataspace_registration_persists_alias_independent_home() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let dataspace =
            crate::sns::dataspace_id_for_sns_alias("paynet").expect("canonical SNS dataspace ID");
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xD7; Hash::LENGTH]));
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: dataspace,
                alias: "paynet".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("catalog");
        tx.nexus.dataspace_catalog = catalog.clone();
        tx.world.dataspace_catalog = catalog;
        seed_dataspace_alias_lease(&mut tx, &authority, "paynet");
        tx.current_dataspace_id = Some(dataspace);
        tx.world.current_dataspace_id = Some(dataspace);
        tx.nexus.lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    dataspace_id: dataspace,
                    alias: "paynet".to_owned(),
                    visibility: LaneVisibility::Public,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("public lane");
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("fixture", "paynet").expect("synthetic identity seed"),
            "unit".parse().expect("name"),
        );
        let instruction = iroha_data_model::isi::RegisterDataspaceAssetDefinition::new(
            dataspace,
            AssetDefinition::numeric(
                id.clone(),
                "Unit".to_owned(),
                AssetBalancePolicy::DataspaceRestricted,
                None,
            ),
        )
        .expect("direct instruction");
        instruction
            .clone()
            .execute(&authority, &mut tx)
            .expect("register");
        let definition = tx.world.asset_definition(&id).expect("definition");
        assert!(definition.owning_domain().is_none());
        assert!(definition.alias().is_none());
        assert_eq!(definition.owned_by(), &authority);
        assert_eq!(
            tx.world
                .asset_definition_dataspace(&id)
                .expect("valid home registry"),
            Some(dataspace)
        );
        assert!(instruction.execute(&authority, &mut tx).is_err());
        assert_eq!(
            tx.world
                .asset_definition_dataspace(&id)
                .expect("valid home registry"),
            Some(dataspace)
        );
    }
    #[test]
    fn asset_registration_is_independent_of_pre_release_cash_metadata() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("precash", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let asset_name: Name = "usd".parse().expect("asset name");
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id.clone(), asset_name);
        let mut metadata = Metadata::default();
        metadata.insert(
            "offline.enabled".parse().expect("legacy metadata key"),
            Json::new(true),
        );
        let new_definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "USD".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata,
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        assert!(
            tx.world.asset_definition(&definition_id).is_ok(),
            "pre-release cash metadata must not block ordinary registration"
        );
    }
    #[test]
    fn register_global_asset_definition_rejects_restricted_dataspace_home() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let domain_id: DomainId = DomainId::try_new("private-unit", "paynet").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("asset definition name"),
        );
        let new_definition = NewAssetDefinition {
            id: definition_id,
            name: "Private Unit".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: Some(domain_id),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: paynet,
                alias: "paynet".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("dataspace catalog");
        tx.nexus.dataspace_catalog = dataspace_catalog.clone();
        tx.world.dataspace_catalog = dataspace_catalog;
        tx.nexus.lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    dataspace_id: paynet,
                    alias: "paynet".to_owned(),
                    visibility: LaneVisibility::Restricted,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("lane catalog");
        tx.current_dataspace_id = Some(paynet);
        tx.world.current_dataspace_id = Some(paynet);
        let err = Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect_err("restricted dataspaces must not register global asset definitions");
        match err {
            InstructionExecutionError::InvariantViolation(message) => {
                assert!(
                    message.contains("restricted dataspace"),
                    "unexpected invariant message: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn global_asset_definition_in_restricted_dataspace_always_rejects() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let domain_id: DomainId = DomainId::try_new("private-unit", "paynet").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("asset definition name"),
        );
        let new_definition = NewAssetDefinition {
            id: definition_id,
            name: "Private Unit".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: Some(domain_id),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Restricted);
        tx.current_dataspace_id = Some(paynet);
        tx.world.current_dataspace_id = Some(paynet);
        let error = Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect_err("restricted dataspaces must reject global asset definitions");
        assert!(
            error.to_string().contains("restricted dataspace"),
            "unexpected invariant error: {error}"
        );
    }
    #[test]
    fn register_global_asset_definition_allows_public_alias_home_on_authoritative_route() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let domain_id: DomainId = DomainId::try_new("private-unit", "paynet").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let alias: AssetDefinitionAlias = "unit#paynet".parse().expect("alias");
        let new_definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "unit".to_owned(),
            description: None,
            alias: Some(alias.clone()),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: Some(domain_id),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Public);
        tx.current_dataspace_id = Some(paynet);
        tx.world.current_dataspace_id = Some(paynet);
        Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect("public dataspace may home a global asset");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id)
        );
    }
    #[test]
    fn register_global_asset_definition_rejects_public_alias_home_on_wrong_route() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let domain_id: DomainId = DomainId::try_new("private-unit", "paynet").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let alias: AssetDefinitionAlias = "unit#paynet".parse().expect("alias");
        let new_definition = NewAssetDefinition {
            id: definition_id,
            name: "unit".to_owned(),
            description: None,
            alias: Some(alias),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: Some(domain_id),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Public);
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let err = Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect_err("global definition must be registered on its owning-domain route");
        assert!(
            err.to_string().contains("authoritative dataspace"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn universal_asset_alias_cannot_override_restricted_owning_domain() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let domain_id: DomainId = DomainId::try_new("private-unit", "paynet").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let alias: AssetDefinitionAlias = "unit#universal".parse().expect("alias");
        let new_definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "unit".to_owned(),
            description: None,
            alias: Some(alias.clone()),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: Some(domain_id),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Restricted);
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let error = Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect_err("a universal alias cannot change the definition's restricted home");
        assert!(
            error.to_string().contains("restricted dataspace"),
            "{error}"
        );
        assert!(tx.world.asset_definitions.get(&definition_id).is_none());
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
    }
    #[test]
    fn asset_home_more_coverage_register_restricted_policy_allows_restricted_alias_home() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let domain_id: DomainId = DomainId::try_new("restricted-unit", "paynet").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let alias: AssetDefinitionAlias = "unit#restricted-unit.paynet".parse().expect("alias");
        let new_definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "unit".to_owned(),
            description: None,
            alias: Some(alias.clone()),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
            owning_domain: Some(domain_id),
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Restricted);
        tx.current_dataspace_id = Some(paynet);
        tx.world.current_dataspace_id = Some(paynet);
        // Restricted homes stay refused on the domain path exactly as on the direct path.
        let error = Register::asset_definition(new_definition.clone())
            .execute(&authority, &mut tx)
            .expect_err("restricted homes are refused until restricted-home confinement ships");
        assert!(
            error.to_string().contains("public home dataspace"),
            "{error}"
        );
        assert!(tx.world.asset_definitions.get(&definition_id).is_none());
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
        // The same definition and alias register in a public home dataspace.
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Public);
        Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect("restricted-policy definition may use an alias in its public home");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id)
        );
        assert_eq!(
            tx.world
                .asset_definition(&definition_id)
                .expect("definition exists")
                .balance_scope_policy(),
            iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted
        );
    }
    #[test]
    fn register_asset_definition_rejects_missing_explicit_name() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId =
            DomainId::try_new("missing-name", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "usd".parse().expect("asset definition name"),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = Register::asset_definition(AssetDefinition::numeric(
            definition_id,
            "   ".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&authority, &mut tx)
        .expect_err("registration without explicit name must fail");
        assert!(
            err.to_string().contains("invalid asset definition name"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn register_asset_definition_rejects_duplicate_alias() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("alias-test", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let id1 = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "usd1".parse().expect("asset name"),
        );
        let id2 = AssetDefinitionId::derive_from_components(
            domain_id,
            "usd2".parse().expect("asset name"),
        );
        let alias: AssetDefinitionAlias = "USD#universal".parse().expect("alias");
        let first = NewAssetDefinition {
            id: id1,
            name: "USD".to_owned(),
            description: None,
            alias: Some(alias.clone()),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let second = NewAssetDefinition {
            id: id2,
            name: "USD".to_owned(),
            description: None,
            alias: Some(alias),
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(first)
            .execute(&authority, &mut tx)
            .expect("first registration should succeed");
        let err = Register::asset_definition(second)
            .execute(&authority, &mut tx)
            .expect_err("duplicate alias must fail");
        assert!(
            err.to_string().contains("already bound"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn asset_alias_requires_asset_owner_and_independent_domain_namespace_scope() {
        let attacker = (*ALICE_ID).clone();
        let namespace_owner = (*BOB_ID).clone();
        let mut state = test_state_with_authority(&attacker);
        let issuer_domain =
            DomainId::try_new("attacker-issuer", "universal").expect("issuer domain");
        let victim_domain =
            DomainId::try_new("victim", "universal").expect("victim namespace domain");
        seed_domain(&mut state, &issuer_domain, &attacker);
        seed_domain(&mut state, &victim_domain, &namespace_owner);
        seed_account(&mut state, &namespace_owner, &victim_domain);
        let definition_id = AssetDefinitionId::derive_from_components(
            issuer_domain.clone(),
            "usd".parse().expect("asset name"),
        );
        let other_definition_id = AssetDefinitionId::derive_from_components(
            issuer_domain,
            "usd_shadow".parse().expect("asset name"),
        );
        let alias: AssetDefinitionAlias = "usd#victim.universal".parse().expect("alias");
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world.add_account_permission(
            &attacker,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(victim_domain.clone()),
            }),
        );
        let error = Register::asset_definition(
            AssetDefinition::numeric(
                definition_id.clone(),
                "usd".to_owned(),
                AssetBalancePolicy::Global,
                None,
            )
            .with_alias(Some(alias.clone())),
        )
        .execute(&attacker, &mut tx)
        .expect_err("account-alias permission must not confer an asset alias");
        assert!(error.to_string().contains("CanManageAssetDefinitionAlias"));
        assert!(tx.world.asset_definitions.get(&definition_id).is_none());
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
        Register::asset_definition(AssetDefinition::numeric(
            definition_id.clone(),
            "usd".to_owned(),
            AssetBalancePolicy::Global,
            None,
        ))
        .execute(&attacker, &mut tx)
        .expect("register unaliased attacker-owned definition");
        Register::asset_definition(AssetDefinition::numeric(
            other_definition_id.clone(),
            "usd".to_owned(),
            AssetBalancePolicy::Global,
            None,
        ))
        .execute(&attacker, &mut tx)
        .expect("register second unaliased attacker-owned definition");
        let error = SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&attacker, &mut tx)
            .expect_err("asset owner still needs exact victim-domain namespace scope");
        assert!(error.to_string().contains("CanManageAssetDefinitionAlias"));
        assert!(
            tx.world
                .asset_definition_alias_bindings
                .get(&definition_id)
                .is_none()
        );
        tx.world.add_account_permission(
            &namespace_owner,
            Permission::from(CanManageAssetDefinitionAlias {
                scope: AssetDefinitionAliasPermissionScope::Domain(victim_domain.clone()),
            }),
        );
        let error = SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&namespace_owner, &mut tx)
            .expect_err("namespace authority must not replace asset-owner authority");
        assert!(error.to_string().contains("only asset-definition owner"));
        assert!(
            tx.world
                .asset_definition_alias_bindings
                .get(&definition_id)
                .is_none()
        );
        let domain_asset_alias_permission = Permission::from(CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Domain(victim_domain),
        });
        tx.world
            .add_account_permission(&attacker, domain_asset_alias_permission.clone());
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&attacker, &mut tx)
            .expect("delegated exact domain scope and asset ownership authorize binding");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id)
        );
        assert!(
            tx.world
                .remove_account_permission(&attacker, &domain_asset_alias_permission),
            "domain-scoped asset alias permission must be removable"
        );
        tx.world.add_account_permission(
            &attacker,
            Permission::from(CanManageAssetDefinitionAlias {
                scope: AssetDefinitionAliasPermissionScope::Alias(
                    ResolvedAssetDefinitionAliasV1::new(
                        alias.clone(),
                        DataSpaceId::UNIVERSAL,
                        definition_id.clone(),
                    ),
                ),
            }),
        );
        SetAssetDefinitionAlias::clear(definition_id.clone())
            .execute(&attacker, &mut tx)
            .expect("exact asset alias permission authorizes clearing its binding");
        SetAssetDefinitionAlias::bind(other_definition_id, alias.clone(), None)
            .execute(&attacker, &mut tx)
            .expect_err("an exact alias capability must not migrate to another definition");
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&attacker, &mut tx)
            .expect("exact asset alias permission authorizes restoring its binding");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id)
        );
    }
    #[test]
    fn domainless_asset_alias_requires_exact_dataspace_namespace_scope() {
        let authority = (*ALICE_ID).clone();
        let mut state = test_state_with_authority(&authority);
        let issuer_domain =
            DomainId::try_new("dataspace-issuer", "universal").expect("issuer domain");
        seed_domain(&mut state, &issuer_domain, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            issuer_domain,
            "cash".parse().expect("asset name"),
        );
        let alias: AssetDefinitionAlias = "cash#paynet".parse().expect("dataspace-root alias");
        let header = BlockHeader::new(nonzero!(2_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let paynet = DataSpaceId::new(7);
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Public);
        Register::asset_definition(AssetDefinition::numeric(
            definition_id.clone(),
            "cash".to_owned(),
            AssetBalancePolicy::Global,
            None,
        ))
        .execute(&authority, &mut tx)
        .expect("register unaliased definition");
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAssetDefinitionAlias {
                scope: AssetDefinitionAliasPermissionScope::Domain(
                    DomainId::try_new("unrelated", "paynet").expect("unrelated domain scope"),
                ),
            }),
        );
        let error = SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect_err("domain permission must not authorize a dataspace-root alias");
        assert!(error.to_string().contains("CanManageAssetDefinitionAlias"));
        assert!(
            tx.world
                .asset_definition_alias_bindings
                .get(&definition_id)
                .is_none()
        );
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(paynet),
            }),
        );
        let error = SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect_err("account-alias dataspace permission must not authorize asset aliases");
        assert!(error.to_string().contains("CanManageAssetDefinitionAlias"));
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAssetDefinitionAlias {
                scope: AssetDefinitionAliasPermissionScope::Dataspace(paynet),
            }),
        );
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect("delegated exact dataspace scope authorizes domainless binding");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id)
        );
    }
    #[test]
    fn set_asset_definition_alias_updates_world_indexes() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId =
            DomainId::try_new("alias-update", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id, "usd".parse().expect("name"));
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "USD".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        let alias: AssetDefinitionAlias = "USD#universal".parse().expect("alias");
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), Some(11_000))
            .execute(&authority, &mut tx)
            .expect("bind alias");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id),
            "alias index must resolve to definition id"
        );
        let binding = tx
            .world
            .asset_definition_alias_bindings
            .get(&definition_id)
            .expect("binding should be present");
        assert_eq!(binding.alias, alias);
        assert_eq!(binding.lease_expiry_ms, Some(11_000));
        assert_eq!(
            binding.grace_until_ms,
            Some(11_000 + 369u64 * 60 * 60 * 1_000)
        );
        let updated = tx
            .world
            .asset_definition(&definition_id)
            .expect("definition should exist");
        assert_eq!(updated.alias().as_ref(), Some(&binding.alias));
    }
    #[test]
    fn set_asset_definition_alias_clear_removes_indexes() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("alias-clear", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id, "usd".parse().expect("name"));
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "USD".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        let alias: AssetDefinitionAlias = "USD#universal".parse().expect("alias");
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect("bind alias");
        SetAssetDefinitionAlias::clear(definition_id.clone())
            .execute(&authority, &mut tx)
            .expect("clear alias");
        assert!(
            tx.world.asset_definition_aliases.get(&alias).is_none(),
            "alias index should be removed"
        );
        assert!(
            tx.world
                .asset_definition_alias_bindings
                .get(&definition_id)
                .is_none(),
            "binding index should be removed"
        );
        let updated = tx
            .world
            .asset_definition(&definition_id)
            .expect("definition should exist");
        assert!(
            updated.alias().is_none(),
            "definition alias should be cleared"
        );
    }
    #[test]
    fn restricted_asset_alias_preserves_global_definition_home() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("alias-global", "universal").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "unit".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let paynet = DataSpaceId::new(7);
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Restricted);
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register global definition");
        let alias: AssetDefinitionAlias = "unit#paynet".parse().expect("alias");
        let error = SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect_err("a public definition cannot take an alias in a restricted namespace");
        assert!(
            error.to_string().contains("restricted dataspace"),
            "{error}"
        );
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
        assert!(
            tx.world
                .asset_definition(&definition_id)
                .expect("definition")
                .owning_domain()
                .is_none()
        );
    }
    #[test]
    fn set_asset_definition_alias_allows_global_move_to_public_dataspace() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("alias-public", "universal").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id, "unit".parse().expect("name"));
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "unit".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let paynet = DataSpaceId::new(7);
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Public);
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register global definition");
        let alias: AssetDefinitionAlias = "unit#paynet".parse().expect("alias");
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect("public dataspace may home a global asset alias");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id)
        );
    }
    #[test]
    fn asset_home_extra_coverage_set_alias_allows_global_move_to_universal() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("alias-universal", "paynet").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let paynet = DataSpaceId::new(7);
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Restricted);
        tx.world.insert_asset_definition_entry(
            definition_id.clone(),
            AssetDefinition::numeric(
                definition_id.clone(),
                "unit".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                Some(domain_id),
            )
            .build(&authority),
        );
        let alias: AssetDefinitionAlias = "unit#universal".parse().expect("alias");
        let error = SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect_err("a restricted-homed definition keeps its aliases in its home namespace");
        assert!(
            error.to_string().contains("restricted dataspace"),
            "{error}"
        );
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
    }
    #[test]
    fn asset_home_extra_coverage_clear_alias_keeps_global_home_universal() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId =
            DomainId::try_new("alias-clear-universal", "universal").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id, "unit".parse().expect("name"));
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "unit".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register global definition");
        let alias: AssetDefinitionAlias = "unit#universal".parse().expect("alias");
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect("bind universal alias");
        SetAssetDefinitionAlias::clear(definition_id.clone())
            .execute(&authority, &mut tx)
            .expect("clearing alias should leave universal domain fallback");
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
        assert!(
            tx.world
                .asset_definition_alias_bindings
                .get(&definition_id)
                .is_none()
        );
    }
    #[test]
    fn set_asset_definition_alias_clear_preserves_explicit_restricted_ownership() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let paynet = DataSpaceId::new(7);
        let domain_id: DomainId = DomainId::try_new("cash", "paynet").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let definition = AssetDefinition::numeric(
            definition_id.clone(),
            "unit".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
            Some(domain_id.clone()),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Public);
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register explicitly owned restricted-policy definition");
        let alias: AssetDefinitionAlias = "unit#paynet".parse().expect("alias");
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect("bind restricted alias");
        SetAssetDefinitionAlias::clear(definition_id.clone())
            .execute(&authority, &mut tx)
            .expect("clearing a display alias preserves explicit ownership");
        assert!(tx.world.asset_definition_aliases.get(&alias).is_none());
        assert!(
            tx.world
                .asset_definition_alias_bindings
                .get(&definition_id)
                .is_none()
        );
        let stored = tx
            .world
            .asset_definition(&definition_id)
            .expect("definition retained");
        assert_eq!(stored.owning_domain().as_ref(), Some(&domain_id));
        assert_eq!(
            stored.balance_scope_policy(),
            iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted
        );
        assert_eq!(
            tx.world.asset_definition_domains.get(&definition_id),
            Some(&domain_id)
        );
    }
    #[test]
    fn set_asset_definition_alias_allows_restricted_policy_in_restricted_dataspace() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("alias-restricted", "paynet").expect("domain");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "unit".parse().expect("name"),
        );
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let paynet = DataSpaceId::new(7);
        install_dataspace_catalog_with_lane(&mut tx, paynet, "paynet", LaneVisibility::Restricted);
        // Registration refuses restricted homes, so seed the homed definition directly.
        tx.world.insert_asset_definition_entry(
            definition_id.clone(),
            AssetDefinition::numeric(
                definition_id.clone(),
                "unit".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                Some(domain_id),
            )
            .build(&authority),
        );
        let foreign: AssetDefinitionAlias = "unit#universal".parse().expect("alias");
        assert!(
            SetAssetDefinitionAlias::bind(definition_id.clone(), foreign, None)
                .execute(&authority, &mut tx)
                .is_err(),
            "a restricted-homed definition cannot alias another namespace"
        );
        let alias: AssetDefinitionAlias = "unit#paynet".parse().expect("alias");
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), None)
            .execute(&authority, &mut tx)
            .expect("restricted asset alias may use its own restricted home namespace");
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id)
        );
    }
    #[test]
    fn set_contract_alias_updates_world_indexes() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("address");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world
            .contract_instances
            .insert(contract_address.clone(), Hash::new("contract-alias"));
        let alias: ContractAlias = "router::universal".parse().expect("alias");
        seed_contract_alias_manage_permissions(&mut tx, &authority, &alias);
        SetContractAlias::bind(contract_address.clone(), alias.clone(), Some(11_000))
            .execute(&authority, &mut tx)
            .expect("bind contract alias");
        assert_eq!(
            tx.world.contract_aliases.get(&alias),
            Some(&contract_address),
            "alias index must resolve to contract address"
        );
        let binding = tx
            .world
            .contract_alias_bindings
            .get(&contract_address)
            .expect("binding should be present");
        assert_eq!(binding.alias, alias);
        assert_eq!(binding.lease_expiry_ms, Some(11_000));
        assert_eq!(
            binding.grace_until_ms,
            Some(11_000 + 369u64 * 60 * 60 * 1_000)
        );
    }
    #[test]
    fn unprivileged_authority_cannot_bind_privileged_benefit_alias() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let benefit_dataspace = DataSpaceId::new(42);
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            benefit_dataspace,
        )
        .expect("address");
        let alias: ContractAlias = "benefit::benefit".parse().expect("benefit alias");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        install_dataspace_catalog_with_lane(
            &mut tx,
            benefit_dataspace,
            "benefit",
            LaneVisibility::Public,
        );
        tx.world.contract_instances.insert(
            contract_address.clone(),
            Hash::new("malicious-benefit-lookalike"),
        );
        let error = SetContractAlias::bind(contract_address, alias, None)
            .execute(&authority, &mut tx)
            .expect_err("unprivileged alias binding must fail closed");
        assert!(
            error
                .to_string()
                .contains("not permitted to manage contract alias"),
            "unexpected alias authorization error: {error}"
        );
    }
    #[test]
    fn set_contract_alias_allows_active_dynamic_sns_dataspace() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let dynamic_dataspace =
            crate::sns::dataspace_id_for_sns_alias("is").expect("dynamic dataspace id");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            dynamic_dataspace,
        )
        .expect("address");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        seed_dataspace_alias_lease(&mut tx, &authority, "is");
        tx.world.contract_instances.insert(
            contract_address.clone(),
            Hash::new("dynamic-contract-alias"),
        );
        let alias: ContractAlias = "router::is".parse().expect("alias");
        seed_contract_alias_manage_permissions(&mut tx, &authority, &alias);
        SetContractAlias::bind(contract_address.clone(), alias.clone(), Some(11_000))
            .execute(&authority, &mut tx)
            .expect("bind dynamic dataspace contract alias");
        assert_eq!(
            tx.world.contract_aliases.get(&alias),
            Some(&contract_address)
        );
        assert_eq!(
            tx.world
                .contract_alias_bindings
                .get(&contract_address)
                .map(|record| record.alias.clone()),
            Some(alias)
        );
    }
    #[test]
    fn set_contract_alias_rejects_unknown_dynamic_dataspace_alias() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let dynamic_dataspace = DataSpaceId::new(4_242);
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            dynamic_dataspace,
        )
        .expect("address");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world.contract_instances.insert(
            contract_address.clone(),
            Hash::new("dynamic-contract-alias"),
        );
        let err = SetContractAlias::bind(
            contract_address,
            "router::missing".parse().expect("alias"),
            Some(11_000),
        )
        .execute(&authority, &mut tx)
        .expect_err("unknown dynamic dataspace must fail closed");
        let err_debug = format!("{err:?}");
        assert!(
            err_debug.contains("unknown or inactive dataspace alias `missing`"),
            "unexpected error: {err_debug}"
        );
    }
    #[test]
    fn set_contract_alias_clear_allows_stale_undeployed_binding() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("address");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world
            .bind_contract_alias(
                &contract_address,
                "router::universal".parse().expect("alias"),
                None,
                None,
                10_000,
            )
            .expect("seed stale contract alias");
        seed_contract_alias_manage_permissions(
            &mut tx,
            &authority,
            &"router::universal".parse().expect("alias"),
        );
        SetContractAlias::clear(contract_address.clone())
            .execute(&authority, &mut tx)
            .expect("clear should tolerate undeployed stale alias");
        assert!(
            tx.world
                .contract_alias_bindings
                .get(&contract_address)
                .is_none(),
            "binding index should be removed"
        );
        assert!(
            tx.world
                .contract_aliases
                .get(&"router::universal".parse::<ContractAlias>().expect("alias"))
                .is_none(),
            "alias index should be removed"
        );
    }
    #[test]
    fn set_contract_alias_clear_allows_stale_dynamic_dataspace_binding() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let dynamic_dataspace =
            crate::sns::dataspace_id_for_sns_alias("is").expect("dynamic dataspace id");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            dynamic_dataspace,
        )
        .expect("address");
        let alias: ContractAlias = "router::is".parse().expect("alias");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world
            .bind_contract_alias(&contract_address, alias.clone(), None, None, 10_000)
            .expect("seed stale dynamic contract alias");
        seed_contract_alias_manage_permissions_in_dataspace(
            &mut tx,
            &authority,
            alias.name_segment().parse().expect("alias label"),
            alias
                .domain_segment()
                .map(|name| AccountAliasDomain::new(name.parse().expect("alias domain"))),
            dynamic_dataspace,
        );
        SetContractAlias::clear(contract_address.clone())
            .execute(&authority, &mut tx)
            .expect("clear should tolerate undeployed dynamic alias");
        assert!(
            tx.world
                .contract_alias_bindings
                .get(&contract_address)
                .is_none(),
            "binding index should be removed"
        );
        assert!(
            tx.world.contract_aliases.get(&alias).is_none(),
            "alias index should be removed"
        );
    }
    #[test]
    fn set_contract_alias_clear_allows_unknown_dynamic_dataspace_without_binding() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::new(4_242),
        )
        .expect("address");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        SetContractAlias::clear(contract_address.clone())
            .execute(&authority, &mut tx)
            .expect("clear should be a no-op for unknown undeployed dynamic address");
        assert!(
            tx.world
                .contract_alias_bindings
                .get(&contract_address)
                .is_none(),
            "clear should not create a binding"
        );
    }
    #[test]
    fn set_contract_alias_clear_rejects_lease_without_alias() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::new(4_242),
        )
        .expect("address");
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let err = SetContractAlias {
            contract_address,
            alias: None,
            lease_expiry_ms: Some(11_000),
        }
        .execute(&authority, &mut tx)
        .expect_err("lease metadata without alias must fail");
        let err_debug = format!("{err:?}");
        assert!(
            err_debug.contains("lease_expiry_ms requires alias binding"),
            "unexpected error: {err_debug}"
        );
    }
    #[test]
    fn set_contract_alias_rejects_account_alias_collision() {
        let state = test_state();
        let authority = (*ALICE_ID).clone();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("address");
        let label =
            AccountAlias::domainless("router".parse().expect("label"), DataSpaceId::UNIVERSAL);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world
            .contract_instances
            .insert(contract_address.clone(), Hash::new("contract-alias"));
        seed_account_alias_lease(&mut tx, &authority, &label);
        seed_contract_alias_manage_permissions(
            &mut tx,
            &authority,
            &"router::universal".parse().expect("alias"),
        );
        let err = SetContractAlias::bind(
            contract_address,
            "router::universal".parse().expect("alias"),
            Some(11_000),
        )
        .execute(&authority, &mut tx)
        .expect_err("account alias collision must fail");
        assert!(
            err.to_string()
                .contains("collides with an active account alias"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn bind_account_alias_rejects_contract_alias_collision() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("address");
        let label =
            AccountAlias::domainless("router".parse().expect("label"), DataSpaceId::UNIVERSAL);
        let account = Account {
            id: authority.clone(),
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let (account_id, account_value) = account.into_key_value();
        state.world.accounts.insert(account_id, account_value);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        tx.world.add_account_permission(
            &authority,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
            }),
        );
        seed_account_alias_lease(&mut tx, &authority, &label);
        tx.world
            .contract_instances
            .insert(contract_address.clone(), Hash::new("contract-alias"));
        tx.world
            .bind_contract_alias(
                &contract_address,
                "router::universal".parse().expect("alias"),
                Some(11_000),
                Some(11_000 + 369u64 * 60 * 60 * 1_000),
                10_000,
            )
            .expect("seed contract alias");
        let err = EnsureTestAccountAliasBinding {
            account: authority.clone(),
            alias: Some(label),
            lease_expiry_ms: None,
        }
        .execute(&authority, &mut tx)
        .expect_err("contract alias collision must fail");
        assert!(
            err.to_string()
                .contains("collides with an active contract alias"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn set_asset_definition_alias_grace_window_sweeps_after_expiry() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("alias-grace", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id, "usd".parse().expect("name"));
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "USD".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        let alias: AssetDefinitionAlias = "USD#universal".parse().expect("alias");
        let lease_expiry = 11_000_u64;
        let grace_until = lease_expiry + 369u64 * 60 * 60 * 1_000;
        SetAssetDefinitionAlias::bind(definition_id.clone(), alias.clone(), Some(lease_expiry))
            .execute(&authority, &mut tx)
            .expect("bind alias");
        let swept_at_grace = tx.world.sweep_expired_asset_definition_aliases(grace_until);
        assert!(
            swept_at_grace.is_empty(),
            "alias must remain bound while still inside grace window"
        );
        assert_eq!(
            tx.world.asset_definition_aliases.get(&alias),
            Some(&definition_id),
            "alias should still resolve during grace window"
        );
        let swept_after_grace = tx
            .world
            .sweep_expired_asset_definition_aliases(grace_until + 1);
        assert_eq!(
            swept_after_grace,
            vec![definition_id.clone()],
            "sweep should unbind alias after grace window"
        );
        assert!(
            tx.world.asset_definition_aliases.get(&alias).is_none(),
            "alias index should be removed after grace expiry"
        );
        assert!(
            tx.world
                .asset_definition_alias_bindings
                .get(&definition_id)
                .is_none(),
            "binding record should be removed after grace expiry"
        );
    }
    #[test]
    fn set_asset_definition_alias_rejects_expired_lease_at_bind_time() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId =
            DomainId::try_new("alias-past-expiry", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id, "usd".parse().expect("name"));
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "USD".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 10_000, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        let alias: AssetDefinitionAlias = "USD#universal".parse().expect("alias");
        let err = SetAssetDefinitionAlias::bind(definition_id, alias, Some(10_000))
            .execute(&authority, &mut tx)
            .expect_err("expired lease should be rejected");
        let debug = format!("{err:?}");
        assert!(
            debug.contains("lease_expiry_ms must be greater than the current block timestamp"),
            "unexpected error: {debug}"
        );
    }
    #[test]
    fn pre_release_cash_metadata_is_ordinary_metadata() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("precash3", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let asset_name: Name = "gbp".parse().expect("asset name");
        let definition_id =
            AssetDefinitionId::derive_from_components(domain_id.clone(), asset_name);
        let new_definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "GBP".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(new_definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        let metadata_key: Name = "offline.enabled".parse().expect("legacy metadata key");
        SetKeyValue::asset_definition(definition_id.clone(), metadata_key.clone(), Json::new(true))
            .execute(&authority, &mut tx)
            .expect("set ordinary metadata");
        assert_eq!(
            tx.world
                .asset_definition(&definition_id)
                .expect("asset definition remains registered")
                .metadata()
                .get(&metadata_key),
            Some(&Json::new(true))
        );
    }
    #[test]
    fn pre_release_cash_false_metadata_does_not_change_runtime_state() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id = DomainId::try_new("precash-disable", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "cash".parse().expect("asset name"),
        );
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "Cash".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        let metadata_key: Name = "offline.enabled".parse().expect("legacy metadata key");
        SetKeyValue::asset_definition(
            definition_id.clone(),
            metadata_key.clone(),
            Json::new(false),
        )
        .execute(&authority, &mut tx)
        .expect("store ordinary metadata");
        assert_eq!(
            tx.world
                .asset_definition(&definition_id)
                .expect("asset definition remains registered")
                .metadata()
                .get(&metadata_key),
            Some(&Json::new(false))
        );
    }
    #[test]
    fn removing_pre_release_cash_metadata_does_not_change_runtime_state() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id = DomainId::try_new("precash-remove", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "cash".parse().expect("asset name"),
        );
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "Cash".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register asset definition");
        let metadata_key: Name = "offline.enabled".parse().expect("legacy metadata key");
        SetKeyValue::asset_definition(definition_id.clone(), metadata_key.clone(), Json::new(true))
            .execute(&authority, &mut tx)
            .expect("store ordinary metadata");
        RemoveKeyValue::asset_definition(definition_id.clone(), metadata_key.clone())
            .execute(&authority, &mut tx)
            .expect("remove pre-release cash metadata");
        assert!(
            tx.world
                .asset_definition(&definition_id)
                .expect("asset definition remains registered")
                .metadata()
                .get(&metadata_key)
                .is_none(),
            "metadata must be removed"
        );
    }
    #[test]
    fn pre_release_cash_true_metadata_does_not_change_runtime_state() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId =
            DomainId::try_new("precash-metadata-disabled", "universal").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "gbp".parse().expect("asset name"),
        );
        let definition = NewAssetDefinition {
            id: definition_id.clone(),
            name: "GBP".to_owned(),
            description: None,
            alias: None,
            spec: NumericSpec::integer(),
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
            balance_scope_policy: iroha_data_model::asset::AssetBalancePolicy::Global,
            owning_domain: None,
        };
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition(definition)
            .execute(&authority, &mut tx)
            .expect("register baseline asset definition");
        let metadata_key: Name = "offline.enabled".parse().expect("legacy metadata key");
        SetKeyValue::asset_definition(definition_id.clone(), metadata_key.clone(), Json::new(true))
            .execute(&authority, &mut tx)
            .expect("store ordinary metadata");
        assert_eq!(
            tx.world
                .asset_definition(&definition_id)
                .expect("baseline definition remains registered")
                .metadata()
                .get(&metadata_key),
            Some(&Json::new(true)),
            "metadata should be stored unchanged"
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_when_definition_has_repo_agreement_state() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let asset_domain: DomainId = DomainId::try_new("asset", "guard").expect("asset domain id");
        let counterparty_domain: DomainId =
            DomainId::try_new("counter", "guard").expect("counterparty domain");
        seed_domain(&mut state, &asset_domain, &authority);
        seed_domain(&mut state, &counterparty_domain, &authority);
        let initiator = AccountId::new(checked_keypair().public_key().clone());
        let counterparty = AccountId::new(checked_keypair().public_key().clone());
        let asset_definition_id =
            AssetDefinitionId::derive_from_components(asset_domain.clone(), "usd".parse().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition({
            let __asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&authority, &mut tx)
        .expect("register asset definition");
        let repo_id: iroha_data_model::repo::RepoAgreementId =
            "repo_asset_guard".parse().expect("repo agreement id");
        tx.world
            .insert_repo_agreement_entry(iroha_data_model::repo::RepoAgreement::new(
                repo_id,
                initiator.clone(),
                counterparty.clone(),
                iroha_data_model::repo::RepoCashLeg {
                    asset_definition_id: asset_definition_id.clone(),
                    quantity: Quantity::from(10_u32),
                },
                AssetId::new(asset_definition_id.clone(), counterparty.clone()),
                iroha_data_model::repo::RepoCollateralLeg::new(
                    AssetDefinitionId::derive_from_components(
                        asset_domain.clone(),
                        "bond".parse().unwrap(),
                    ),
                    Quantity::from(12_u32),
                ),
                AssetId::new(
                    AssetDefinitionId::derive_from_components(
                        asset_domain,
                        "bond".parse().unwrap(),
                    ),
                    counterparty,
                ),
                250,
                1_000,
                1,
                iroha_data_model::repo::RepoGovernance::new(1_000, 60, false),
                None,
            ));
        let err = Unregister::asset_definition(asset_definition_id.clone())
            .execute(&authority, &mut tx)
            .expect_err("asset definition with repo agreement reference must not be unregistered");
        let err_string = err.to_string();
        assert!(
            err_string.contains("repo agreement state"),
            "error should explain repo agreement conflict: {err_string}"
        );
        assert!(
            tx.world
                .asset_definitions
                .get(&asset_definition_id)
                .is_some(),
            "asset definition should remain after rejected unregister"
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_when_definition_is_governance_voting_asset() {
        with_registered_asset_definition_unregistration_candidate_with_policy(
            |state, asset_definition_id| {
                state.gov.voting_asset_id = asset_definition_id.clone();
            },
            |authority, asset_definition_id, tx| {
                let err = Unregister::asset_definition(asset_definition_id.clone())
                    .execute(&authority, tx)
                    .expect_err("governance voting asset definition must not be unregistered");
                let err_string = err.to_string();
                assert!(
                    err_string.contains("governance voting asset definition"),
                    "error should explain governance voting-asset conflict: {err_string}"
                );
                assert!(
                    tx.world
                        .asset_definitions
                        .get(&asset_definition_id)
                        .is_some(),
                    "asset definition should remain after rejected unregister"
                );
            },
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_immutable_governance_lock_custody_after_config_change() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let asset_domain: DomainId = DomainId::try_new("asset", "guard").expect("asset domain id");
        seed_domain(&mut state, &asset_domain, &authority);
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            asset_domain.clone(),
            "locked".parse().unwrap(),
        );
        state.gov.voting_asset_id =
            AssetDefinitionId::derive_from_components(asset_domain, "replacement".parse().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition({
            let __asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "locked".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&authority, &mut tx)
        .expect("register retained custody asset definition");
        let owner = (*BOB_ID).clone();
        let mut locks = GovernanceLocksForReferendum::default();
        locks.locks.insert(
            owner.clone(),
            GovernanceLockRecord {
                owner,
                amount: Quantity::from(150_u32),
                slashed: Quantity::zero(),
                expiry_height: 10,
                direction: 0,
                duration_blocks: 3_600,
                custody: GovernanceLockCustody {
                    escrowed: true,
                    asset_definition_id: asset_definition_id.clone(),
                    bond_escrow_account: authority.clone(),
                    slash_receiver_account: authority.clone(),
                },
            },
        );
        tx.world
            .put_governance_locks("retained-asset-custody".to_owned(), locks);
        let err = Unregister::asset_definition(asset_definition_id.clone())
            .execute(&authority, &mut tx)
            .expect_err("immutable lock custody asset definition must remain registered");
        assert!(
            err.to_string()
                .contains("retained by immutable governance lock custody"),
            "error should identify retained lock custody: {err}"
        );
        assert!(
            tx.world
                .asset_definitions
                .get(&asset_definition_id)
                .is_some(),
            "custody asset definition must remain after rejected unregister"
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_retained_moderation_policy_after_config_change() {
        with_registered_asset_definition_unregistration_candidate(
            |authority, asset_definition_id, tx| {
                assert_ne!(
                    tx.gov.voting_asset_id, asset_definition_id,
                    "the candidate must not rely on the current governance config guard"
                );
                crate::smartcontracts::isi::sorafs_moderation::seed_moderation_policy_asset_reference_for_test(
                    &mut tx.world,
                    asset_definition_id.clone(),
                    authority.clone(),
                    authority.clone(),
                )
                .expect("seed a valid retained moderation policy");
                let policy_key: iroha_model_base::state_path::StatePath =
                    "sorafs_moderation_policy_v1"
                        .parse()
                        .expect("moderation policy state path");
                let policy_before = tx.world.smart_contract_state.get(&policy_key).cloned();

                let error = Unregister::asset_definition(asset_definition_id.clone())
                    .execute(&authority, tx)
                    .expect_err("moderation-retained asset definition must remain registered");
                assert!(
                    error
                        .to_string()
                        .contains("retained by moderation active policy challenge voting asset"),
                    "unexpected moderation retention error: {error}"
                );
                assert!(
                    tx.world
                        .asset_definitions
                        .get(&asset_definition_id)
                        .is_some(),
                    "moderation-retained definition must remain after rejected unregister"
                );
                assert_eq!(
                    tx.world.smart_contract_state.get(&policy_key),
                    policy_before.as_ref(),
                    "rejected unregister must not mutate moderation state"
                );
            },
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_when_definition_is_governance_viral_reward_asset() {
        with_registered_asset_definition_unregistration_candidate_with_policy(
            |state, asset_definition_id| {
                state.gov.viral_incentives.reward_asset_definition_id = asset_definition_id.clone();
            },
            |authority, asset_definition_id, tx| {
                let err = Unregister::asset_definition(asset_definition_id.clone())
                    .execute(&authority, tx)
                    .expect_err(
                        "governance viral reward asset definition must not be unregistered",
                    );
                let err_string = err.to_string();
                assert!(
                    err_string.contains("governance viral reward asset definition"),
                    "error should explain governance viral reward-asset conflict: {err_string}"
                );
                assert!(
                    tx.world
                        .asset_definitions
                        .get(&asset_definition_id)
                        .is_some(),
                    "asset definition should remain after rejected unregister"
                );
            },
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_when_definition_is_oracle_reward_asset() {
        with_registered_asset_definition_unregistration_candidate_with_policy(
            |state, asset_definition_id| {
                state.oracle.economics.reward_asset = asset_definition_id.clone();
            },
            |authority, asset_definition_id, tx| {
                let err = Unregister::asset_definition(asset_definition_id.clone())
                    .execute(&authority, tx)
                    .expect_err("oracle reward asset definition must not be unregistered");
                let err_string = err.to_string();
                assert!(
                    err_string.contains("oracle reward asset definition"),
                    "error should explain oracle reward-asset conflict: {err_string}"
                );
                assert!(
                    tx.world
                        .asset_definitions
                        .get(&asset_definition_id)
                        .is_some(),
                    "asset definition should remain after rejected unregister"
                );
            },
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_when_definition_is_nexus_fee_asset() {
        with_registered_asset_definition_unregistration_candidate(
            |authority, asset_definition_id, tx| {
                tx.nexus.fees.fee_asset_id = asset_definition_id.clone();
                let err = Unregister::asset_definition(asset_definition_id.clone())
                    .execute(&authority, tx)
                    .expect_err("nexus fee asset definition must not be unregistered");
                let err_string = err.to_string();
                assert!(
                    err_string.contains("immutable committed root fee currency"),
                    "error should explain nexus fee-asset conflict: {err_string}"
                );
                assert!(
                    tx.world
                        .asset_definitions
                        .get(&asset_definition_id)
                        .is_some(),
                    "asset definition should remain after rejected unregister"
                );
            },
        );
    }
    #[test]
    fn unregister_asset_definition_preserves_pinned_staking_custody_after_config_change() {
        with_registered_asset_definition_unregistration_candidate(
            |authority, asset_definition_id, tx| {
                tx.nexus.staking.stake_asset_id = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("replacement", "universal").unwrap(),
                    "stake".parse().unwrap(),
                )
                .to_string();
                let asset = AssetId::new(asset_definition_id.clone(), authority.clone());
                let key = (LaneId::SINGLE, authority.clone());
                tx.world
                    .public_lane_stake_custody
                    .insert(key.clone(), (asset.clone(), Quantity::one()));
                for has_custody_row in [true, false] {
                    let reserves_before = tx.world.public_lane_stake_reserves.get(&asset).cloned();
                    let error = Unregister::asset_definition(asset_definition_id.clone())
                        .execute(&authority, tx)
                        .expect_err("pinned stake definition must remain registered");
                    assert!(
                        error
                            .to_string()
                            .contains("pinned public-lane staking custody"),
                        "{error}"
                    );
                    assert!(
                        tx.world
                            .asset_definitions
                            .get(&asset_definition_id)
                            .is_some()
                    );
                    assert_eq!(
                        tx.world.public_lane_stake_reserves.get(&asset),
                        reserves_before.as_ref()
                    );
                    if has_custody_row {
                        tx.world.public_lane_stake_custody.remove(key.clone());
                        tx.world
                            .public_lane_stake_reserves
                            .insert(asset.clone(), Quantity::one());
                    }
                }
                tx.world.public_lane_stake_reserves.remove(asset);
                Unregister::asset_definition(asset_definition_id.clone())
                    .execute(&authority, tx)
                    .expect("former stake definition can be removed after liability release");
                assert!(
                    tx.world
                        .asset_definitions
                        .get(&asset_definition_id)
                        .is_none()
                );
            },
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_when_definition_is_nexus_staking_asset() {
        with_registered_asset_definition_unregistration_candidate(
            |authority, asset_definition_id, tx| {
                tx.nexus.staking.stake_asset_id = asset_definition_id.to_string();
                let err = Unregister::asset_definition(asset_definition_id.clone())
                    .execute(&authority, tx)
                    .expect_err("nexus staking asset definition must not be unregistered");
                let err_string = err.to_string();
                assert!(
                    err_string.contains("nexus staking asset definition"),
                    "error should explain nexus staking-asset conflict: {err_string}"
                );
                assert!(
                    tx.world
                        .asset_definitions
                        .get(&asset_definition_id)
                        .is_some(),
                    "asset definition should remain after rejected unregister"
                );
            },
        );
    }
    #[test]
    fn unregister_asset_definition_removes_associated_permissions_from_accounts_and_roles() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let asset_domain: DomainId = DomainId::try_new("asset", "guard").expect("asset domain id");
        let holder_domain: DomainId =
            DomainId::try_new("holder", "guard").expect("holder domain id");
        seed_domain(&mut state, &asset_domain, &authority);
        seed_domain(&mut state, &holder_domain, &authority);
        let asset_definition_id =
            AssetDefinitionId::derive_from_components(asset_domain.clone(), "usd".parse().unwrap());
        let asset_account = AccountId::new(checked_keypair().public_key().clone());
        let holder_id = AccountId::new(checked_keypair().public_key().clone());
        let asset_id = AssetId::new(asset_definition_id.clone(), asset_account.clone());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::account(NewAccount::new(asset_account.clone()))
            .execute(&authority, &mut tx)
            .expect("register asset account");
        Register::account(NewAccount::new(holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register holder account");
        Register::asset_definition({
            let __asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&authority, &mut tx)
        .expect("register asset definition");
        let alias: AssetDefinitionAlias = "usd#universal".parse().expect("asset alias");
        let bound_at_ms = tx.block_unix_timestamp_ms();
        tx.world
            .bind_asset_definition_alias(
                &asset_definition_id,
                alias.clone(),
                None,
                None,
                bound_at_ms,
            )
            .expect("bind exact-permission fixture alias");
        let permission_with_definition: Permission = iroha_executor_data_model::permission::asset_definition::CanModifyAssetDefinitionMetadata {
            asset_definition: asset_definition_id.clone(),
        }
        .into();
        let permission_with_confidential_policy: Permission = iroha_executor_data_model::permission::asset_definition::CanManageAssetDefinitionConfidentialPolicy {
            asset_definition: asset_definition_id.clone(),
        }
        .into();
        let permission_with_exact_alias: Permission = CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Alias(ResolvedAssetDefinitionAliasV1::new(
                alias,
                DataSpaceId::UNIVERSAL,
                asset_definition_id.clone(),
            )),
        }
        .into();
        let permission_with_asset: Permission =
            iroha_executor_data_model::permission::asset::CanModifyAssetMetadata {
                asset: asset_id.clone(),
            }
            .into();
        let lifecycle_permissions = [
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetTransferAvailability {
                    account: asset_account.clone(),
                    asset_definition: asset_definition_id.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetTransferDailyLimit {
                    asset_definition: asset_definition_id.clone(),
                    account_domain: asset_domain.name().clone().into(),
                    account_dataspace: DataSpaceId::UNIVERSAL,
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetHoldingLimit {
                    account: asset_account.clone(),
                    asset_definition: asset_definition_id.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::settlement::CanExecuteSettlement {
                    debited_asset: asset_id,
                    settlement_id: iroha_data_model::isi::SettlementId::new(
                        asset_account.clone(),
                        "asset_cleanup_consent"
                            .parse()
                            .expect("settlement reference"),
                    ),
                    intent_hash: Hash::new(b"asset-definition cleanup consent"),
                },
            ),
        ];
        Grant::account_permission(permission_with_definition.clone(), holder_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant definition permission to holder");
        Grant::account_permission(
            permission_with_confidential_policy.clone(),
            holder_id.clone(),
        )
        .execute(&authority, &mut tx)
        .expect("grant confidential policy permission to holder");
        Grant::account_permission(permission_with_asset.clone(), holder_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant asset permission to holder");
        Grant::account_permission(permission_with_exact_alias.clone(), holder_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant exact alias permission to holder");
        for permission in &lifecycle_permissions {
            Grant::account_permission(permission.clone(), holder_id.clone())
                .execute(&authority, &mut tx)
                .expect("grant lifecycle permission to holder");
        }
        let role_id: RoleId = "ASSET_CLEANUP".parse().expect("role id");
        Register::role(Role::new(role_id.clone(), holder_id.clone()))
            .execute(&authority, &mut tx)
            .expect("register role");
        Grant::role_permission(permission_with_definition.clone(), role_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant definition permission to role");
        Grant::role_permission(permission_with_confidential_policy.clone(), role_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant confidential policy permission to role");
        Grant::role_permission(permission_with_asset.clone(), role_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant asset permission to role");
        Grant::role_permission(permission_with_exact_alias.clone(), role_id.clone())
            .execute(&authority, &mut tx)
            .expect("grant exact alias permission to role");
        for permission in &lifecycle_permissions {
            Grant::role_permission(permission.clone(), role_id.clone())
                .execute(&authority, &mut tx)
                .expect("grant lifecycle permission to role");
        }
        assert!(
            tx.world
                .account_permissions
                .get(&holder_id)
                .is_some_and(|perms| {
                    perms.contains(&permission_with_definition)
                        && perms.contains(&permission_with_confidential_policy)
                        && perms.contains(&permission_with_asset)
                        && perms.contains(&permission_with_exact_alias)
                        && lifecycle_permissions
                            .iter()
                            .all(|permission| perms.contains(permission))
                }),
            "holder should have permissions before unregister"
        );
        let role = tx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            role.permissions()
                .any(|perm| perm == &permission_with_definition),
            "role should include definition permission before unregister"
        );
        assert!(
            role.permissions()
                .any(|perm| perm == &permission_with_confidential_policy),
            "role should include confidential policy permission before unregister"
        );
        assert!(
            role.permissions()
                .any(|perm| perm == &permission_with_asset),
            "role should include asset permission before unregister"
        );
        assert!(
            role.permissions()
                .any(|perm| perm == &permission_with_exact_alias),
            "role should include exact alias permission before unregister"
        );
        assert!(
            lifecycle_permissions
                .iter()
                .all(|permission| role.permissions().any(|candidate| candidate == permission)),
            "role should include lifecycle permissions before unregister"
        );
        Unregister::asset_definition(asset_definition_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister asset definition");
        assert!(
            !tx.world
                .account_permissions
                .get(&holder_id)
                .is_some_and(|perms| {
                    perms.contains(&permission_with_definition)
                        || perms.contains(&permission_with_confidential_policy)
                        || perms.contains(&permission_with_asset)
                        || perms.contains(&permission_with_exact_alias)
                        || lifecycle_permissions
                            .iter()
                            .any(|permission| perms.contains(permission))
                }),
            "holder permissions should be removed"
        );
        let role = tx.world.roles.get(&role_id).expect("role should exist");
        assert!(
            !role
                .permissions()
                .any(|perm| perm == &permission_with_confidential_policy),
            "role confidential policy permission should be removed"
        );
        assert!(
            !role
                .permissions()
                .any(|perm| perm == &permission_with_definition),
            "role definition permission should be removed"
        );
        assert!(
            !role
                .permissions()
                .any(|perm| perm == &permission_with_asset),
            "role asset permission should be removed"
        );
        assert!(
            !role
                .permissions()
                .any(|perm| perm == &permission_with_exact_alias),
            "role exact alias permission should be removed"
        );
        assert!(
            lifecycle_permissions
                .iter()
                .all(|permission| !role.permissions().any(|candidate| candidate == permission)),
            "role lifecycle permissions should be removed"
        );
        assert!(
            !role
                .permission_epochs()
                .contains_key(&permission_with_confidential_policy),
            "confidential policy permission epoch should be pruned"
        );
        assert!(
            !role
                .permission_epochs()
                .contains_key(&permission_with_definition),
            "definition permission epoch should be pruned"
        );
        assert!(
            !role
                .permission_epochs()
                .contains_key(&permission_with_asset),
            "asset permission epoch should be pruned"
        );
        assert!(
            !role
                .permission_epochs()
                .contains_key(&permission_with_exact_alias),
            "exact alias permission epoch should be pruned"
        );
    }
    #[test]
    fn unregister_asset_definition_rejects_when_definition_has_committed_settlement_receipt() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let asset_domain: DomainId = DomainId::try_new("asset", "guard").expect("asset domain id");
        let counterparty_domain: DomainId =
            DomainId::try_new("counter", "guard").expect("counterparty domain");
        seed_domain(&mut state, &asset_domain, &authority);
        seed_domain(&mut state, &counterparty_domain, &authority);
        let from = AccountId::new(checked_keypair().public_key().clone());
        let to = AccountId::new(checked_keypair().public_key().clone());
        let asset_definition_id =
            AssetDefinitionId::derive_from_components(asset_domain, "usd".parse().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition({
            let __asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&authority, &mut tx)
        .expect("register asset definition");
        let settlement_id: iroha_data_model::isi::SettlementId =
            iroha_data_model::isi::SettlementId::new(
                from.clone(),
                "settle_asset_guard".parse().expect("settlement reference"),
            );
        let receipt = iroha_data_model::isi::SettlementReceipt {
            authority: from.clone(),
            metadata: Metadata::default(),
            block_height: 1,
            block_hash:
                iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                    Hash::prehashed([0; Hash::LENGTH]),
                ),
            executed_at_ms: 1,
            details: iroha_data_model::isi::SettlementDetails::Dvp(
                iroha_data_model::isi::DvpSettlementDetails {
                    delivery: {
                        let leg = iroha_data_model::isi::SettlementLeg::new(
                            asset_definition_id.clone(),
                            Quantity::one(),
                            from.clone(),
                            to.clone(),
                        );
                        iroha_data_model::isi::ResolvedSettlementMovement {
                            source: AssetId::with_scope(
                                leg.asset_definition_id().clone(),
                                leg.from().clone(),
                                iroha_data_model::asset::AssetBalanceScope::Global,
                            ),
                            destination: AssetId::with_scope(
                                leg.asset_definition_id().clone(),
                                leg.to().clone(),
                                iroha_data_model::asset::AssetBalanceScope::Global,
                            ),
                            quantity: leg.quantity().clone(),
                            metadata: leg.metadata().clone(),
                        }
                    },
                    payment: {
                        let leg = iroha_data_model::isi::SettlementLeg::new(
                            AssetDefinitionId::derive_from_components(
                                counterparty_domain,
                                "eur".parse().expect("asset name"),
                            ),
                            Quantity::one(),
                            to,
                            from,
                        );
                        iroha_data_model::isi::ResolvedSettlementMovement {
                            source: AssetId::with_scope(
                                leg.asset_definition_id().clone(),
                                leg.from().clone(),
                                iroha_data_model::asset::AssetBalanceScope::Global,
                            ),
                            destination: AssetId::with_scope(
                                leg.asset_definition_id().clone(),
                                leg.to().clone(),
                                iroha_data_model::asset::AssetBalanceScope::Global,
                            ),
                            quantity: leg.quantity().clone(),
                            metadata: leg.metadata().clone(),
                        }
                    },
                    order: iroha_data_model::isi::SettlementExecutionOrder::DeliveryThenPayment,
                },
            ),
        };
        tx.world.settlement_receipts.insert(settlement_id, receipt);
        let err = Unregister::asset_definition(asset_definition_id.clone())
            .execute(&authority, &mut tx)
            .expect_err(
                "asset definition with a committed settlement receipt must not be unregistered",
            );
        let err_string = err.to_string();
        assert!(
            err_string.contains("committed settlement receipt"),
            "error should explain settlement receipt conflict: {err_string}"
        );
        assert!(
            tx.world
                .asset_definitions
                .get(&asset_definition_id)
                .is_some(),
            "asset definition should remain after rejected unregister"
        );
    }

    #[test]
    fn unregister_asset_definition_removes_confidential_state() {
        let mut state = test_state();
        let authority = (*ALICE_ID).clone();
        let domain_id: DomainId = DomainId::try_new("zk", "guard").expect("domain id");
        seed_domain(&mut state, &domain_id, &authority);
        let asset_definition_id =
            AssetDefinitionId::derive_from_components(domain_id, "shield".parse().unwrap());
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        Register::asset_definition({
            let __asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "shield".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&authority, &mut tx)
        .expect("register asset definition");
        tx.world.zk_assets.insert(
            asset_definition_id.clone(),
            crate::state::ZkAssetState::default(),
        );
        Unregister::asset_definition(asset_definition_id.clone())
            .execute(&authority, &mut tx)
            .expect("unregister asset definition");
        assert!(
            tx.world
                .asset_definitions
                .get(&asset_definition_id)
                .is_none(),
            "asset definition should be removed"
        );
        assert!(
            tx.world.zk_assets.get(&asset_definition_id).is_none(),
            "confidential state should be removed with asset definition"
        );
    }
}
