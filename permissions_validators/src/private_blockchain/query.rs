//! Query Permissions.

use super::*;

/// Allow queries that only access the data of the domain of the signer.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct OnlyAccountsDomain;

impl IsAllowed<QueryBox> for OnlyAccountsDomain {
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn check(
        &self,
        authority: &AccountId,
        query: &QueryBox,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        use QueryBox::*;
        let context = Context::new();
        match query {
            FindAssetsByAssetDefinitionId(_) | FindAssetsByName(_) | FindAllAssets(_) => {
                Err("Only access to the assets of the same domain is permitted."
                    .to_owned()
                    .into())
            }
            FindAllAccounts(_) | FindAccountsByName(_) | FindAccountsWithAsset(_) => Err(
                "Only access to the accounts of the same domain is permitted."
                    .to_owned()
                    .into(),
            ),
            FindAllAssetsDefinitions(_) => Err(
                "Only access to the asset definitions of the same domain is permitted."
                    .to_owned()
                    .into(),
            ),
            FindAllDomains(_) => Err("Only access to the domain of the account is permitted."
                .to_owned()
                .into()),
            FindAllRoles(_) => Err("Only access to roles of the same domain is permitted."
                .to_owned()
                .into()),
            FindAllRoleIds(_) => Ok(()), // In case you need to debug the permissions.
            FindRoleByRoleId(_) => Err("Only access to roles of the same domain is permitted."
                .to_owned()
                .into()),
            FindAllPeers(_) => Ok(()), // Can be obtained in other ways, so why hide it.
            FindAllActiveTriggerIds(_) => Ok(()),
            // Private blockchains should have debugging too, hence
            // all accounts should also be
            FindTriggerById(query) => {
                let id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|e| e.to_string())?;
                wsv.triggers()
                    .inspect(&id, |action| {
                        if action.technical_account() == authority {
                            Ok(())
                        } else {
                            Err("Cannot access Trigger if you're not the technical account."
                                .to_owned()
                                .into())
                        }
                    })
                    .ok_or_else(|| {
                        format!(
                            "A trigger with the specified Id: {} is not accessible to you",
                            id.clone()
                        )
                    })?
            }
            FindTriggerKeyValueByIdAndKey(query) => {
                let id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|e| e.to_string())?;
                wsv.triggers()
                    .inspect(&id, |action| {
                        if action.technical_account() == authority {
                            Ok(())
                        } else {
                            Err(
                        "Cannot access Trigger internal state if you're not the technical account."
                            .to_owned().into(),
                    )
                        }
                    })
                    .ok_or_else(|| {
                        format!(
                            "A trigger with the specified Id: {} is not accessible to you",
                            id.clone()
                        )
                    })?
            }
            FindTriggersByDomainId(query) => {
                let domain_id = query
                    .domain_id
                    .evaluate(wsv, &context)
                    .map_err(|e| e.to_string())?;

                if domain_id == authority.domain_id {
                    return Ok(());
                }

                Err(format!(
                    "Cannot access triggers with given domain {}, {} is permitted..",
                    domain_id, authority.domain_id
                )
                .into())
            }
            FindAccountById(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    )
                    .into())
                }
            }
            FindAccountKeyValueByIdAndKey(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    )
                    .into())
                }
            }
            FindAccountsByDomainId(query) => {
                let domain_id = query
                    .domain_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access accounts from a different domain with name {}.",
                        domain_id
                    )
                    .into())
                }
            }
            FindAssetById(query) => {
                let asset_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if asset_id.account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset {} as it is in a different domain.",
                        asset_id
                    )
                    .into())
                }
            }
            FindAssetsByAccountId(query) => {
                let account_id = query
                    .account_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    )
                    .into())
                }
            }
            FindAssetsByDomainId(query) => {
                let domain_id = query
                    .domain_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access assets from a different domain with name {}.",
                        domain_id
                    )
                    .into())
                }
            }
            FindAssetsByDomainIdAndAssetDefinitionId(query) => {
                let domain_id = query
                    .domain_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access assets from a different domain with name {}.",
                        domain_id
                    )
                    .into())
                }
            }
            FindAssetDefinitionKeyValueByIdAndKey(query) => {
                let asset_definition_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if asset_definition_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset definition from a different domain. Asset definition domain: {}. Signer's account domain {}.",
                        asset_definition_id.domain_id,
                        authority.domain_id
                    ).into())
                }
            }
            FindAssetQuantityById(query) => {
                let asset_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if asset_id.account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset {} as it is in a different domain.",
                        asset_id
                    )
                    .into())
                }
            }
            FindAssetKeyValueByIdAndKey(query) => {
                let asset_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if asset_id.account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset {} as it is in a different domain.",
                        asset_id
                    )
                    .into())
                }
            }
            FindDomainById(query::FindDomainById { id })
            | FindDomainKeyValueByIdAndKey(query::FindDomainKeyValueByIdAndKey { id, .. }) => {
                let domain_id = id.evaluate(wsv, &context).map_err(|err| err.to_string())?;
                if domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!("Cannot access a different domain: {}.", domain_id).into())
                }
            }
            FindAllBlocks(_) => Err("Access to all blocks not permitted".to_owned().into()),
            FindAllTransactions(_) => Err(
                "Only access to transactions in the same domain is permitted."
                    .to_owned()
                    .into(),
            ),
            FindTransactionsByAccountId(query) => {
                let account_id = query
                    .account_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    )
                    .into())
                }
            }
            FindTransactionByHash(_query) => Ok(()),
            FindRolesByAccountId(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    )
                    .into())
                }
            }
            FindPermissionTokensByAccountId(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if account_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as it is in a different domain.",
                        account_id
                    )
                    .into())
                }
            }
            FindAssetDefinitionById(query) => {
                let asset_definition_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;

                if asset_definition_id.domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset definition from a different domain. Asset definition domain: {}. Signer's account domain {}.",
                        asset_definition_id.domain_id,
                        authority.domain_id,
                    ).into())
                }
            }
        }
    }
}

impl_from_item_for_query_validator_box!(OnlyAccountsDomain);

/// Allow queries that only access the signers account data.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct OnlyAccountsData;

impl IsAllowed<QueryBox> for OnlyAccountsData {
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn check(
        &self,
        authority: &AccountId,
        query: &QueryBox,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        use QueryBox::*;

        let context = Context::new();
        match query {
            FindAccountsByName(_)
                | FindAccountsByDomainId(_)
                | FindAccountsWithAsset(_)
                | FindAllAccounts(_) => {
                    Err("Other accounts are private.".to_owned().into())
                }
                | FindAllDomains(_)
                | FindDomainById(_)
                | FindDomainKeyValueByIdAndKey(_) => {
                    Err("Only access to your account's data is permitted.".to_owned().into())
                },
            FindAssetsByDomainIdAndAssetDefinitionId(_)
                | FindAssetsByName(_) // TODO: I think this is a mistake.
                | FindAssetsByDomainId(_)
                | FindAllAssetsDefinitions(_)
                | FindAssetsByAssetDefinitionId(_)
                | FindAssetDefinitionById(_)
                | FindAssetDefinitionKeyValueByIdAndKey(_)
                | FindAllAssets(_) => {
                    Err("Only access to the assets of your account is permitted.".to_owned().into())
                }
            FindAllRoles(_) | FindAllRoleIds(_) | FindRoleByRoleId(_) => {
                Err("Only access to roles of the same account is permitted.".to_owned().into())
            },
            FindAllActiveTriggerIds(_) | FindTriggersByDomainId(_) => {
                Err("Only access to the triggers of the same account is permitted.".to_owned().into())
            }
            FindAllPeers(_) => {
                Err("Only access to your account-local data is permitted.".to_owned().into())
            }
            FindTriggerById(query) => {
                // TODO: should differentiate between global and domain-local triggers.
                let id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|e| e.to_string())?;
                if wsv.triggers().inspect(&id, |action|
                    action.technical_account() == authority
                ) == Some(true) {
                    return Ok(())
                }
                Err(format!(
                    "A trigger with the specified Id: {} is not accessible to you",
                    id
                ).into())
            }
            FindTriggerKeyValueByIdAndKey(query) => {
                // TODO: should differentiate between global and domain-local triggers.
                let id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if wsv.triggers().inspect(&id, |action|
                    action.technical_account() == authority
                ) == Some(true) {
                    return Ok(())
                }
                Err(format!(
                    "A trigger with the specified Id: {} is not accessible to you",
                    id
                ).into())
            }
            FindAccountById(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &account_id == authority {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as only access to your own account, {} is permitted..",
                        account_id,
                        authority
                    ).into())
                }
            }
            FindAccountKeyValueByIdAndKey(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &account_id == authority {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access account {} as only access to your own account is permitted..",
                        account_id
                    ).into())
                }
            }
            FindAssetById(query) => {
                let asset_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &asset_id.account_id == authority {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset {} as it is in a different account.",
                        asset_id
                    ).into())
                }
            }
            FindAssetsByAccountId(query) => {
                let account_id = query
                    .account_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &account_id == authority {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access a different account: {}.",
                        account_id
                    ).into())
                }
            }

            FindAssetQuantityById(query) => {
                let asset_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &asset_id.account_id == authority {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset {} as it is in a different account.",
                        asset_id
                    ).into())
                }
            }
            FindAssetKeyValueByIdAndKey(query) => {
                let asset_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &asset_id.account_id == authority {
                    Ok(())
                } else {
                    Err(format!(
                        "Cannot access asset {} as it is in a different account.",
                        asset_id
                    ).into())
                }
            }
            FindAllBlocks(_) => {
                Err("Access to all blocks not permitted".to_owned().into())
            }
            FindAllTransactions(_) => {
                Err("Only access to transactions of the same account is permitted.".to_owned().into())
            },
            FindTransactionsByAccountId(query) => {
                let account_id = query
                    .account_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &account_id == authority {
                    Ok(())
                } else {
                    Err(format!("Cannot access another account: {}.", account_id).into())
                }
            }
            FindTransactionByHash(_query) => Ok(()),
            FindRolesByAccountId(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &account_id == authority {
                    Ok(())
                } else {
                    Err(format!("Cannot access another account: {}.", account_id).into())
                }
            }
            FindPermissionTokensByAccountId(query) => {
                let account_id = query
                    .id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &account_id == authority {
                    Ok(())
                } else {
                    Err(format!("Cannot access another account: {}.", account_id).into())
                }
            }
        }
    }
}

impl_from_item_for_query_validator_box!(OnlyAccountsData);
