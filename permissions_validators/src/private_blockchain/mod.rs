//! Permission checks associated with use cases that can be summarized as private blockchains (e.g. CBDC).

use super::*;

pub mod query;
pub mod register;

/// A preconfigured set of permissions for simple use cases.
pub fn default_instructions_permissions() -> IsInstructionAllowedBoxed {
    ValidatorBuilder::with_recursive_validator(
        register::ProhibitRegisterDomains.or(register::GrantedAllowedRegisterDomains),
    )
    .all_should_succeed()
    .build()
}

/// A preconfigured set of permissions for simple use cases.
pub fn default_query_permissions() -> IsQueryAllowedBoxed {
    ValidatorBuilder::with_validator(AllowAll)
        .all_should_succeed()
        .build()
}

/// Prohibits using the [`Grant`] instruction at runtime.  This means
/// `Grant` instruction will only be used in genesis to specify
/// rights. The rationale is that we don't want to be able to create a
/// super-user in a blockchain.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct ProhibitGrant;

impl_from_item_for_grant_instruction_validator_box!(ProhibitGrant);

impl IsGrantAllowed for ProhibitGrant {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &GrantBox,
        _wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        Err("Granting at runtime is prohibited.".to_owned().into())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr as _;

    use super::*;

    /// A test environment that contains test domains, accounts, and assets.
    struct TestEnv {
        /// Alice's Id that owns Gold and Bronze assets.
        alice_id: AccountId,
        /// Bob's Id that owns Silver asset.
        bob_id: AccountId,
        /// Carol's Id that owns Bronze asset.
        carol_id: AccountId,
        /// Gold asset's Id.
        gold_asset_id: AssetId,
        /// Gold asset definition's Id.
        gold_asset_definition_id: AssetDefinitionId,
        /// Silver asset's Id.
        silver_asset_id: AssetId,
        /// Silver asset definition's Id.
        silver_asset_definition_id: AssetDefinitionId,
        /// Bronze asset's Id.
        bronze_asset_id: AssetId,
        /// Bronze asset definition's Id.
        bronze_asset_definition_id: AssetDefinitionId,
        /// Wonderland is a domain that contains Alice and Bob
        wonderland: (DomainId, Domain),
        /// Denoland is a domain that contains Carol
        denoland: (DomainId, Domain),
        /// World state view contains wonderland and denoland domains.
        wsv: WorldStateView,
        /// A trigger that mints Gold asset and created by Alice
        mintbox_gold_trigger_id: TriggerId,
    }

    impl TestEnv {
        /// Creates a test environment
        fn new() -> Self {
            let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
            let mut alice = Account::new(alice_id.clone(), []).build();

            let gold_asset_definition_id =
                AssetDefinitionId::from_str("gold#wonderland").expect("Valid");
            let gold_asset_id = AssetId::new(gold_asset_definition_id.clone(), alice_id.clone());
            let gold_asset = Asset::new(gold_asset_id.clone(), AssetValue::Quantity(100));

            alice.add_asset(gold_asset);

            let bob_id = AccountId::from_str("bob@wonderland").expect("Valid");
            let mut bob = Account::new(bob_id.clone(), []).build();

            let silver_asset_definition_id =
                AssetDefinitionId::from_str("silver#wonderland").expect("Valid");
            let silver_asset_id = AssetId::new(silver_asset_definition_id.clone(), bob_id.clone());
            let silver_asset = Asset::new(silver_asset_id.clone(), AssetValue::Quantity(200));

            bob.add_asset(silver_asset);

            let carol_id = AccountId::from_str("carol@denoland").expect("Valid");
            let mut carol = Account::new(carol_id.clone(), []).build();

            let bronze_asset_definition_id =
                AssetDefinitionId::from_str("bronze#denoland").expect("Valid");
            let bronze_asset_id =
                AssetId::new(bronze_asset_definition_id.clone(), carol_id.clone());
            let bronze_asset = Asset::new(bronze_asset_id.clone(), AssetValue::Quantity(300));

            carol.add_asset(bronze_asset.clone());

            alice.add_asset(bronze_asset);

            let wonderland_id = DomainId::from_str("wonderland").expect("Valid");
            let mut wonderland = Domain::new(wonderland_id.clone()).build();

            wonderland.add_account(alice);

            wonderland.add_account(bob);

            let denoland_id = DomainId::from_str("denoland").expect("Valid");
            let mut denoland = Domain::new(denoland_id.clone()).build();

            denoland.add_account(carol);

            let world = World::with([wonderland.clone(), denoland.clone()], Vec::new());

            let wsv = WorldStateView::new(world);

            let mintbox_gold_trigger_id =
                TriggerId::from_str("mint_box_gold_asset").expect("Valid");

            wsv.modify_triggers(|triggers| {
                let trigger_instructions = vec![MintBox::new(1_u32, gold_asset_id.clone()).into()];
                let trigger: Trigger<FilterBox> = Trigger::new(
                    mintbox_gold_trigger_id.clone(),
                    Action::new(
                        Executable::from(trigger_instructions),
                        Repeats::Indefinitely,
                        alice_id.clone(),
                        FilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
                    ),
                );

                triggers.add_time_trigger(trigger.try_into().expect("Valid"));

                Ok(TriggerEvent::Created(mintbox_gold_trigger_id.clone()))
            })
            .expect("Valid");

            Self {
                alice_id,
                bob_id,
                carol_id,
                gold_asset_id,
                gold_asset_definition_id,
                silver_asset_id,
                silver_asset_definition_id,
                bronze_asset_id,
                bronze_asset_definition_id,
                wonderland: (wonderland_id, wonderland),
                denoland: (denoland_id, denoland),
                mintbox_gold_trigger_id,
                wsv,
            }
        }
    }

    mod queries {
        use super::*;

        #[test]
        fn find_all_accounts() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let op = QueryBox::FindAllAccounts(FindAllAccounts::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_err());
                assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_err());
            }
        }

        #[test]
        fn find_account_by_id() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let op = QueryBox::FindAccountById(FindAccountById::new(alice_id.clone()));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_ok());
                assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_ok());
                assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_ok());
                assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_err());
            }
        }

        #[test]
        fn find_account_key_value_by_id_and_key() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let op = QueryBox::FindAccountKeyValueByIdAndKey(FindAccountKeyValueByIdAndKey::new(
                alice_id.clone(),
                "name".to_owned(),
            ));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_ok());
                assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_ok());
                assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_ok());
                assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_err());
            }
        }

        #[test]
        fn find_account_by_name() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let op = QueryBox::FindAccountsByName(FindAccountsByName::new(alice_id.clone()));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_err());
                assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_err());
            }
        }

        #[test]
        fn find_accounts_by_domain_id() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wonderland: (wonderland_id, _),
                denoland: (second_domain_id, _),
                wsv,
                ..
            } = TestEnv::new();

            let find_by_first_domain =
                QueryBox::FindAccountsByDomainId(FindAccountsByDomainId::new(wonderland_id));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_by_first_domain, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_by_first_domain, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_by_first_domain, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_by_first_domain, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_by_first_domain, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_by_first_domain, &wsv)
                    .is_err());
            }

            let find_by_second_domain =
                QueryBox::FindAccountsByDomainId(FindAccountsByDomainId::new(second_domain_id));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_by_second_domain, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_by_second_domain, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_by_second_domain, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_by_second_domain, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_by_second_domain, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_by_second_domain, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_accounts_with_asset() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let op = QueryBox::FindAccountsWithAsset(FindAccountsWithAsset::new("xor".to_owned()));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_err());
                assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_err());
            }
        }

        #[test]
        fn find_all_assets() {
            let TestEnv { alice_id, wsv, .. } = TestEnv::new();

            let op = QueryBox::FindAllAssets(FindAllAssets::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_err());
            }
        }

        #[test]
        fn find_all_assets_definitions() {
            let TestEnv { alice_id, wsv, .. } = TestEnv::new();

            let op = QueryBox::FindAllAssetsDefinitions(FindAllAssetsDefinitions::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_err());
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
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_silver, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_bronze, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_bronze, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&alice_id, &find_silver, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_bronze, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&alice_id, &find_bronze, &wsv)
                    .is_err());
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

            let find_gold = QueryBox::FindAssetDefinitionById(FindAssetDefinitionById::new(
                gold_asset_definition_id,
            ));
            let find_silver = QueryBox::FindAssetDefinitionById(FindAssetDefinitionById::new(
                silver_asset_definition_id,
            ));
            let find_bronze = QueryBox::FindAssetDefinitionById(FindAssetDefinitionById::new(
                bronze_asset_definition_id,
            ));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_silver, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_bronze, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_bronze, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_silver, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_bronze, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_bronze, &wsv)
                    .is_err());
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
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_silver, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_bronze, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_bronze, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_silver, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_bronze, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_bronze, &wsv)
                    .is_err());
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
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain.check(&alice_id, &op, &wsv).is_ok());
                assert!(only_accounts_domain.check(&bob_id, &op, &wsv).is_ok());
                assert!(only_accounts_domain.check(&carol_id, &op, &wsv).is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data.check(&alice_id, &op, &wsv).is_ok());
                assert!(only_accounts_data.check(&bob_id, &op, &wsv).is_err());
                assert!(only_accounts_data.check(&carol_id, &op, &wsv).is_err());
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

            let find_gold = QueryBox::FindAssetsByAssetDefinitionId(
                FindAssetsByAssetDefinitionId::new(gold_asset_definition_id),
            );

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_gold, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_gold, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold, &wsv)
                    .is_err());
                assert!(only_accounts_data.check(&bob_id, &find_gold, &wsv).is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_gold, &wsv)
                    .is_err());
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
            let find_by_denoland =
                QueryBox::FindAssetsByDomainId(FindAssetsByDomainId::new(denoland_id));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_by_wonderland, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_by_denoland, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_by_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_by_denoland, &wsv)
                    .is_err())
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
                FindAssetsByDomainIdAndAssetDefinitionId::new(
                    denoland_id,
                    bronze_asset_definition_id,
                ),
            );

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold_by_wonderland, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold_by_denoland, &wsv)
                    .is_err());

                assert!(only_accounts_domain
                    .check(&alice_id, &find_bronze_by_wonderland, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_bronze_by_denoland, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold_by_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_gold_by_denoland, &wsv)
                    .is_err());

                assert!(only_accounts_data
                    .check(&alice_id, &find_bronze_by_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_bronze_by_denoland, &wsv)
                    .is_err());
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
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold_quantity, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_gold_quantity, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_bronze_quantity, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_gold_quantity, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_bronze_quantity, &wsv)
                    .is_ok());
            }
            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold_quantity, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&bob_id, &find_silver_quantity, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&carol_id, &find_bronze_quantity, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&alice_id, &find_silver_quantity, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_bronze_quantity, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_gold_quantity, &wsv)
                    .is_err());
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
            let find_gold_key_value = QueryBox::FindAssetKeyValueByIdAndKey(
                FindAssetKeyValueByIdAndKey::new(gold_asset_id, "foo".to_string()),
            );
            let find_silver_key_value = QueryBox::FindAssetKeyValueByIdAndKey(
                FindAssetKeyValueByIdAndKey::new(silver_asset_id, "foo".to_string()),
            );
            let find_bronze_key_value = QueryBox::FindAssetKeyValueByIdAndKey(
                FindAssetKeyValueByIdAndKey::new(bronze_asset_id, "foo".to_string()),
            );

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_gold_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_bronze_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_gold_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_bronze_key_value, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&bob_id, &find_silver_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&carol_id, &find_bronze_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&alice_id, &find_silver_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_gold_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_bronze_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_gold_key_value, &wsv)
                    .is_err());
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
            let find_gold_key_value = QueryBox::FindAssetDefinitionKeyValueByIdAndKey(
                FindAssetDefinitionKeyValueByIdAndKey::new(
                    gold_asset_definition_id,
                    "foo".to_string(),
                ),
            );
            let find_silver_key_value = QueryBox::FindAssetDefinitionKeyValueByIdAndKey(
                FindAssetDefinitionKeyValueByIdAndKey::new(
                    silver_asset_definition_id,
                    "foo".to_string(),
                ),
            );
            let find_bronze_key_value = QueryBox::FindAssetDefinitionKeyValueByIdAndKey(
                FindAssetDefinitionKeyValueByIdAndKey::new(
                    bronze_asset_definition_id,
                    "foo".to_string(),
                ),
            );
            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_gold_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_gold_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_bronze_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_gold_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_bronze_key_value, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_gold_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_silver_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_bronze_key_value, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_all_domains() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_all_domains = QueryBox::FindAllDomains(FindAllDomains::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_all_domains, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_all_domains, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_all_domains, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_all_domains, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_all_domains, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_all_domains, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_domain_by_id() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wonderland: (wonderland_id, _),
                wsv,
                ..
            } = TestEnv::new();

            let find_wonderland = QueryBox::FindDomainById(FindDomainById::new(wonderland_id));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_wonderland, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_wonderland, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_wonderland, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_wonderland, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_domain_key_value_by_id_and_key() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wonderland: (wonderland_id, _),
                wsv,
                ..
            } = TestEnv::new();

            let find_wonderland_key_value = QueryBox::FindDomainKeyValueByIdAndKey(
                FindDomainKeyValueByIdAndKey::new(wonderland_id, "foo".to_string()),
            );

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_wonderland_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_wonderland_key_value, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_wonderland_key_value, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_wonderland_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_wonderland_key_value, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_wonderland_key_value, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_all_peers() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_all_peers = QueryBox::FindAllPeers(FindAllPeers::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                // Always allow do it for any account.
                assert!(only_accounts_domain
                    .check(&alice_id, &find_all_peers, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_all_peers, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_all_peers, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                // Always returns an error for any account.
                assert!(only_accounts_data
                    .check(&alice_id, &find_all_peers, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_all_peers, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_all_peers, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_all_blocks() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_all_blocks = QueryBox::FindAllBlocks(FindAllBlocks::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                // Always returns an error for any account.
                assert!(only_accounts_domain
                    .check(&alice_id, &find_all_blocks, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_all_blocks, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_all_blocks, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                // Always returns an error for any account.
                assert!(only_accounts_data
                    .check(&alice_id, &find_all_blocks, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_all_blocks, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_all_blocks, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_all_transactions() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_all_transactions = QueryBox::FindAllTransactions(FindAllTransactions::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                // Always returns an error for any account.
                assert!(only_accounts_domain
                    .check(&alice_id, &find_all_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_all_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_all_transactions, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                // Always returns an error for any account.
                assert!(only_accounts_data
                    .check(&alice_id, &find_all_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_all_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_all_transactions, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_transactions_by_account_id() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_alice_transactions = QueryBox::FindTransactionsByAccountId(
                FindTransactionsByAccountId::new(alice_id.clone()),
            );
            let find_bob_transactions = QueryBox::FindTransactionsByAccountId(
                FindTransactionsByAccountId::new(bob_id.clone()),
            );
            let find_carol_transactions = QueryBox::FindTransactionsByAccountId(
                FindTransactionsByAccountId::new(carol_id.clone()),
            );

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_alice_transactions, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_carol_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_alice_transactions, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_bob_transactions, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_alice_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_carol_transactions, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_alice_transactions, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&alice_id, &find_carol_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_alice_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_bob_transactions, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&carol_id, &find_alice_transactions, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_carol_transactions, &wsv)
                    .is_ok());
            }
        }

        #[test]
        fn find_transaction_by_hash() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_alice_transaction =
                QueryBox::FindTransactionByHash(FindTransactionByHash::new(Hash::new(&[])));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                // Always allow for any account.
                assert!(only_accounts_domain
                    .check(&alice_id, &find_alice_transaction, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_alice_transaction, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_alice_transaction, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                // Always allow for any account.
                assert!(only_accounts_data
                    .check(&alice_id, &find_alice_transaction, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&bob_id, &find_alice_transaction, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&carol_id, &find_alice_transaction, &wsv)
                    .is_ok());
            }
        }

        #[test]
        fn find_permission_tokens_by_account_id() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_alice_permission_tokens =
                QueryBox::FindPermissionTokensByAccountId(FindPermissionTokensByAccountId {
                    id: alice_id.clone().into(),
                });
            let find_bob_permission_tokens =
                QueryBox::FindPermissionTokensByAccountId(FindPermissionTokensByAccountId {
                    id: bob_id.clone().into(),
                });
            let find_carol_permission_tokens =
                QueryBox::FindPermissionTokensByAccountId(FindPermissionTokensByAccountId {
                    id: carol_id.clone().into(),
                });

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_alice_permission_tokens, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_carol_permission_tokens, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_alice_permission_tokens, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_bob_permission_tokens, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_alice_permission_tokens, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_carol_permission_tokens, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_alice_permission_tokens, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&alice_id, &find_carol_permission_tokens, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_alice_permission_tokens, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_bob_permission_tokens, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&carol_id, &find_alice_permission_tokens, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_carol_permission_tokens, &wsv)
                    .is_ok());
            }
        }

        #[test]
        fn find_all_active_trigger_ids() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_all_active_triggers =
                QueryBox::FindAllActiveTriggerIds(FindAllActiveTriggerIds {});

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                // Always allow for any account.
                assert!(only_accounts_domain
                    .check(&alice_id, &find_all_active_triggers, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_all_active_triggers, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_all_active_triggers, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                // Always returns an error for any account.
                assert!(only_accounts_data
                    .check(&alice_id, &find_all_active_triggers, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_all_active_triggers, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_all_active_triggers, &wsv)
                    .is_err());
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
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_trigger, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_trigger, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_trigger, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_trigger, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&bob_id, &find_trigger, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_trigger, &wsv)
                    .is_err());
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

            let find_trigger =
                QueryBox::FindTriggerKeyValueByIdAndKey(FindTriggerKeyValueByIdAndKey {
                    id: mintbox_gold_trigger_id.into(),
                    key: "foo".to_string().into(),
                });

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_trigger, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_trigger, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_trigger, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_trigger, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&bob_id, &find_trigger, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_trigger, &wsv)
                    .is_err());
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
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_trigger_by_wonderland, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&alice_id, &find_trigger_by_denoland, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_trigger_by_wonderland, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_trigger_by_denoland, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_trigger_by_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_trigger_by_denoland, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_trigger_by_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&alice_id, &find_trigger_by_denoland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_trigger_by_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_trigger_by_denoland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_trigger_by_wonderland, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_trigger_by_denoland, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_all_roles() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_all_roles = QueryBox::FindAllRoles(FindAllRoles::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_all_roles, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_all_roles, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_all_roles, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_all_roles, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_all_roles, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_all_roles, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_all_role_ids() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_all_role_ids = QueryBox::FindAllRoleIds(FindAllRoleIds::new());

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_all_role_ids, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_all_role_ids, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_all_role_ids, &wsv)
                    .is_ok());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_all_role_ids, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_all_role_ids, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_all_role_ids, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_roles_by_account_id() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_by_alice =
                QueryBox::FindRolesByAccountId(FindRolesByAccountId::new(alice_id.clone()));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_by_alice, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_by_alice, &wsv)
                    .is_ok());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_by_alice, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_by_alice, &wsv)
                    .is_ok());
                assert!(only_accounts_data
                    .check(&bob_id, &find_by_alice, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_by_alice, &wsv)
                    .is_err());
            }
        }

        #[test]
        fn find_role_by_role_id() {
            let TestEnv {
                alice_id,
                bob_id,
                carol_id,
                wsv,
                ..
            } = TestEnv::new();

            let find_by_admin =
                QueryBox::FindRoleByRoleId(FindRoleByRoleId::new("admin".to_string()));

            {
                let only_accounts_domain: IsQueryAllowedBoxed = query::OnlyAccountsDomain.into();

                assert!(only_accounts_domain
                    .check(&alice_id, &find_by_admin, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&bob_id, &find_by_admin, &wsv)
                    .is_err());
                assert!(only_accounts_domain
                    .check(&carol_id, &find_by_admin, &wsv)
                    .is_err());
            }

            {
                let only_accounts_data: IsQueryAllowedBoxed = query::OnlyAccountsData.into();

                assert!(only_accounts_data
                    .check(&alice_id, &find_by_admin, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&bob_id, &find_by_admin, &wsv)
                    .is_err());
                assert!(only_accounts_data
                    .check(&carol_id, &find_by_admin, &wsv)
                    .is_err());
            }
        }
    }

    mod revoke_and_grant {
        use super::*;

        #[test]
        fn add_register_domains_permission_denies_registering_domain() {
            let alice_id = AccountId::from_str("alice@test0").expect("Valid");

            let instruction = Instruction::Register(RegisterBox::new(Domain::new(
                "new_domain".parse().expect("Valid"),
            )));

            let wsv = WorldStateView::new(World::new());

            assert!(register::ProhibitRegisterDomains
                .check(&alice_id, &instruction, &wsv)
                .is_err());
        }

        #[test]
        fn add_register_domains_permission_allows_registering_account() {
            let alice_id = AccountId::from_str("alice@test0").expect("Valid");

            let instruction = Instruction::Register(RegisterBox::new(Account::new(
                "bob@test".parse().expect("Valid"),
                [],
            )));

            let wsv = WorldStateView::new(World::new());

            assert!(register::ProhibitRegisterDomains
                .check(&alice_id, &instruction, &wsv)
                .is_ok());
        }

        #[test]
        fn add_register_domains_permission_allows_registering_domain_with_right_token() {
            let alice_id = AccountId::from_str("alice@test0").expect("Valid");

            let mut alice = Account::new(alice_id.clone(), []).build();
            alice.add_permission(register::CanRegisterDomains::new().into());

            let bob_id = AccountId::from_str("bob@test0").expect("Valid");
            let bob = Account::new(bob_id.clone(), []).build();

            let domain_id = DomainId::from_str("test0").expect("Valid");
            let mut domain = Domain::new(domain_id).build();
            domain.add_account(alice.clone());
            domain.add_account(bob);

            let wsv = WorldStateView::new(World::with([domain], Vec::new()));

            let validator: IsInstructionAllowedBoxed =
                register::GrantedAllowedRegisterDomains.into();

            let op = Instruction::Register(RegisterBox::new(Domain::new(
                "newdomain".parse().expect("Valid"),
            )));

            assert!(validator.check(&alice_id, &op, &wsv).is_ok());
            assert!(validator.check(&bob_id, &op, &wsv).is_err());
        }

        #[test]
        fn add_register_domains_permission_denies_registering_domain_with_wrong_token() {
            let alice_id = AccountId::from_str("alice@test0").expect("Valid");

            let mut alice = Account::new(alice_id.clone(), []).build();
            alice.add_permission(PermissionToken::new(
                Name::from_str("incorrecttoken").expect("Valid"),
            ));

            let domain_id = DomainId::from_str("test0").expect("Valid");
            let mut domain = Domain::new(domain_id).build();
            domain.add_account(alice.clone());

            let wsv = WorldStateView::new(World::with([domain], Vec::new()));

            let validator: IsInstructionAllowedBoxed =
                register::GrantedAllowedRegisterDomains.into();

            let op = Instruction::Register(RegisterBox::new(Domain::new(
                "newdomain".parse().expect("Valid"),
            )));

            assert!(validator.check(&alice_id, &op, &wsv).is_err());
        }
    }
}
