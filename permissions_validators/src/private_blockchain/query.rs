//! Query Permissions.

use iroha_core::smartcontracts::permissions::ValidatorVerdict;

use super::*;

/// Allow queries that only access the data of the domain of the signer.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow queries that only access the data for the domain of the signer")]
pub struct OnlyAccountsDomain;

impl IsAllowed for OnlyAccountsDomain {
    type Operation = QueryBox;

    #[allow(
        clippy::too_many_lines,
        clippy::match_same_arms,
        clippy::cognitive_complexity
    )]
    fn check(
        &self,
        authority: &AccountId,
        query: &QueryBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        use QueryBox::*;
        match query {
            FindAssetsByAssetDefinitionId(_) | FindAssetsByName(_) | FindAllAssets(_) => {
                Deny("Only access to the assets of the same domain is permitted.".to_owned())
            }
            FindAllAccounts(_) | FindAccountsByName(_) | FindAccountsWithAsset(_) => {
                Deny("Only access to the accounts of the same domain is permitted.".to_owned())
            }
            FindAllAssetsDefinitions(_) => Deny(
                "Only access to the asset definitions of the same domain is permitted.".to_owned(),
            ),
            FindAllDomains(_) => {
                Deny("Only access to the domain of the account is permitted.".to_owned())
            }
            FindAllRoles(_) => {
                Deny("Only access to roles of the same domain is permitted.".to_owned())
            }
            FindAllRoleIds(_) => Allow, // In case you need to debug the permissions.
            FindAllPermissionTokenDefinitions(_) => Allow, // Same
            FindRoleByRoleId(_) => {
                Deny("Only access to roles of the same domain is permitted.".to_owned())
            }
            FindAllPeers(_) => Allow, // Can be obtained in other ways, so why hide it.
            FindAllActiveTriggerIds(_) => Allow,
            // Private blockchains should have debugging too, hence
            // all accounts should also be
            FindTriggerById(query) => {
                let id = try_evaluate_or_deny!(query.id, wsv);
                wsv.triggers()
                    .inspect_by_id(&id, |action| {
                        if action.technical_account() == authority {
                            Allow
                        } else {
                            Deny("Only technical accounts can access triggers.".to_owned())
                        }
                    })
                    .unwrap_or_else(|| {
                        Deny(format!(
                            "A trigger with the specified Id: {} is not accessible to you",
                            id.clone()
                        ))
                    })
            }
            FindTriggerKeyValueByIdAndKey(query) => {
                let id = try_evaluate_or_deny!(query.id, wsv);
                wsv.triggers()
                    .inspect_by_id(&id, |action| {
                        if action.technical_account() == authority {
                            Allow
                        } else {
                            Deny(
                                "Only technical accounts can access the internal state of a Trigger."
                                .to_owned()
                            )
                        }
                    })
                    .unwrap_or_else(|| {
                        Deny(
                            format!(
                                "A trigger with the specified Id: {} is not accessible to you",
                                id.clone()
                            ),
                        )
                    })
            }
            FindTriggersByDomainId(query) => {
                let domain_id = try_evaluate_or_deny!(query.domain_id, wsv);

                if domain_id == authority.domain_id {
                    return Allow;
                }

                Deny(format!(
                    "Cannot access triggers with given domain {}, {} is permitted..",
                    domain_id, authority.domain_id
                ))
            }
            FindAccountById(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    ))
                }
            }
            FindAccountKeyValueByIdAndKey(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    ))
                }
            }
            FindAccountsByDomainId(query) => {
                let domain_id = try_evaluate_or_deny!(query.domain_id, wsv);
                if domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access accounts from a different domain with name {}.",
                        domain_id
                    ))
                }
            }
            FindAssetById(query) => {
                let asset_id = try_evaluate_or_deny!(query.id, wsv);
                if asset_id.account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset {} as it is in a different domain.",
                        asset_id
                    ))
                }
            }
            FindAssetsByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query.account_id, wsv);
                if account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    ))
                }
            }
            FindAssetsByDomainId(query) => {
                let domain_id = try_evaluate_or_deny!(query.domain_id, wsv);
                if domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access assets from a different domain with name {}.",
                        domain_id
                    ))
                }
            }
            FindAssetsByDomainIdAndAssetDefinitionId(query) => {
                let domain_id = try_evaluate_or_deny!(query.domain_id, wsv);
                if domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access assets from a different domain with name {}.",
                        domain_id
                    ))
                }
            }
            FindAssetDefinitionKeyValueByIdAndKey(query) => {
                let asset_definition_id = try_evaluate_or_deny!(query.id, wsv);
                if asset_definition_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset definition from a different domain. Asset definition domain: {}. Signer's account domain {}.",
                        asset_definition_id.domain_id,
                        authority.domain_id
                    ))
                }
            }
            FindAssetQuantityById(query) => {
                let asset_id = try_evaluate_or_deny!(query.id, wsv);
                if asset_id.account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset {} as it is in a different domain.",
                        asset_id
                    ))
                }
            }
            FindAssetKeyValueByIdAndKey(query) => {
                let asset_id = try_evaluate_or_deny!(query.id, wsv);
                if asset_id.account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset {} as it is in a different domain.",
                        asset_id
                    ))
                }
            }
            FindDomainById(query::FindDomainById { id })
            | FindDomainKeyValueByIdAndKey(query::FindDomainKeyValueByIdAndKey { id, .. }) => {
                let domain_id = try_evaluate_or_deny!(id, wsv);
                if domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!("Cannot access a different domain: {}.", domain_id))
                }
            }
            FindAllBlocks(_) => Deny("You are not permitted to access all blocks.".to_owned()),
            FindAllBlockHeaders(_) => {
                Deny("You are not permitted to access all blocks.".to_owned())
            }
            FindBlockHeaderByHash(_) => {
                Deny("You are not permitted to access arbitrary blocks.".to_owned())
            }
            FindAllTransactions(_) => {
                Deny("Cannot access transactions of another domain.".to_owned())
            }
            FindTransactionsByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query.account_id, wsv);
                if account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    ))
                }
            }
            FindTransactionByHash(_query) => Allow,
            FindRolesByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    ))
                }
            }
            FindPermissionTokensByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if account_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    ))
                }
            }
            FindAssetDefinitionById(query) => {
                let asset_definition_id = try_evaluate_or_deny!(query.id, wsv);

                if asset_definition_id.domain_id == authority.domain_id {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset definition from a different domain. Asset definition domain: {}. Signer's account domain {}.",
                        asset_definition_id.domain_id,
                        authority.domain_id,
                    ))
                }
            }
        }
    }
}

/// Allow queries that only access the signers account data.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow queries that only access the signers account data")]
pub struct OnlyAccountsData;

impl IsAllowed for OnlyAccountsData {
    type Operation = QueryBox;

    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn check(
        &self,
        authority: &AccountId,
        query: &QueryBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        use QueryBox::*;

        match query {
            FindAccountsByName(_)
                | FindAccountsByDomainId(_)
                | FindAccountsWithAsset(_)
                | FindAllAccounts(_) => {
                    Deny("Other accounts are private.".to_owned())
                }
                | FindAllDomains(_)
                | FindDomainById(_)
                | FindDomainKeyValueByIdAndKey(_) => {
                    Deny("Only the access to the data in your own account is permitted.".to_owned())
                },
            FindAssetsByDomainIdAndAssetDefinitionId(_)
                | FindAssetsByName(_) // TODO: I think this is a mistake.
                | FindAssetsByDomainId(_)
                | FindAllAssetsDefinitions(_)
                | FindAssetsByAssetDefinitionId(_)
                | FindAssetDefinitionById(_)
                | FindAssetDefinitionKeyValueByIdAndKey(_)
                | FindAllAssets(_) => {
                    Deny("Only the access to the assets of your own account is permitted.".to_owned())
                }
            FindAllRoles(_) | FindAllRoleIds(_) | FindRoleByRoleId(_) => {
                Deny("Only the access to the roles of your own account is permitted.".to_owned())
            },
            FindAllActiveTriggerIds(_) | FindTriggersByDomainId(_) => {
                Deny("Only the access to the triggers of your own account is permitted.".to_owned())
            }
            FindAllPeers(_) => {
                Deny("Only the access to the local data of your account is permitted.".to_owned())
            }
            FindTriggerById(query) => {
                // TODO: should differentiate between global and domain-local triggers.
                let id = try_evaluate_or_deny!(query.id, wsv);
                if wsv.triggers().inspect_by_id(&id, |action|
                    action.technical_account() == authority
                ) == Some(true) {
                    return Allow
                }
                Deny(format!(
                    "A trigger with the specified Id: {} is not accessible to you",
                    id
                ))
            }
            FindTriggerKeyValueByIdAndKey(query) => {
                // TODO: should differentiate between global and domain-local triggers.
                let id = try_evaluate_or_deny!(query.id, wsv);
                if wsv.triggers().inspect_by_id(&id, |action|
                    action.technical_account() == authority
                ) == Some(true) {
                    return Allow
                }
                Deny(format!(
                    "A trigger with the specified Id: {} is not accessible to you",
                    id
                ))
            }
            FindAccountById(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if &account_id == authority {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as only access to your own account, {} is permitted..",
                        account_id,
                        authority
                    ))
                }
            }
            FindAccountKeyValueByIdAndKey(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if &account_id == authority {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access account {} as only access to your own account is permitted..",
                        account_id
                    ))
                }
            }
            FindAssetById(query) => {
                let asset_id = try_evaluate_or_deny!(query.id, wsv);
                if &asset_id.account_id == authority {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset {} as it is in a different account.",
                        asset_id
                    ))
                }
            }
            FindAssetsByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query
                    .account_id, wsv);
                if &account_id == authority {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access a different account: {}.",
                        account_id
                    ))
                }
            }

            FindAssetQuantityById(query) => {
                let asset_id = try_evaluate_or_deny!(query.id, wsv);
                if &asset_id.account_id == authority {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset {} as it is in a different account.",
                        asset_id
                    ))
                }
            }
            FindAssetKeyValueByIdAndKey(query) => {
                let asset_id = try_evaluate_or_deny!(query.id, wsv);
                if &asset_id.account_id == authority {
                    Allow
                } else {
                    Deny(format!(
                        "Cannot access asset {} as it is in a different account.",
                        asset_id
                    ))
                }
            }
            FindAllBlocks(_) => {
                Deny("You are not permitted to access all blocks.".to_owned())
            }
            FindAllBlockHeaders(_) => {
                Deny("Access to all block headers not permitted".to_owned())
            }
            FindBlockHeaderByHash(_) => {
                Deny("Access to arbitrary block headers not permitted".to_owned())
            }
            FindAllTransactions(_) => {
                Deny("Cannot access transactions of another account.".to_owned())
            },
            FindTransactionsByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query
                    .account_id, wsv);
                if &account_id == authority {
                    Allow
                } else {
                    Deny(format!("Cannot access another account: {}.", account_id))
                }
            }
            FindTransactionByHash(_query) => Allow,
            FindRolesByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if &account_id == authority {
                    Allow
                } else {
                    Deny(format!("Cannot access another account: {}.", account_id))
                }
            }
            FindAllPermissionTokenDefinitions(_) => Deny("Only the access to the permission tokens of your own account is permitted.".to_owned()),
            FindPermissionTokensByAccountId(query) => {
                let account_id = try_evaluate_or_deny!(query.id, wsv);
                if &account_id == authority {
                    Allow
                } else {
                    Deny(format!("Cannot access another account: {}.", account_id))
                }
            }
        }
    }
}
