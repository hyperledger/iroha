//! Query Permissions.

use super::*;

/// Allow queries that only access the data of the domain of the signer.
#[derive(Debug, Copy, Clone)]
pub struct OnlyAccountsDomain;

impl<W: WorldTrait> IsAllowed<W, QueryBox> for OnlyAccountsDomain {
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn check(
        &self,
        authority: &AccountId,
        query: &QueryBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        use QueryBox::*;
        let context = Context::new();
        match query {
            FindAssetsByAssetDefinitionId(_) | FindAssetsByName(_) | FindAllAssets(_) => {
                Err("Only access to the assets of the same domain is permitted.".to_owned())
            }
            FindAllAccounts(_) | FindAccountsByName(_) => {
                Err("Only access to the accounts of the same domain is permitted.".to_owned())
            }
            FindAllAssetsDefinitions(_) => Err(
                "Only access to the asset definitions of the same domain is permitted.".to_owned(),
            ),
            FindAllDomains(_) => {
                Err("Only access to the domain of the account is permitted.".to_owned())
            }
            FindAllRoles(_) => Ok(()),
            FindAllPeers(_) => Ok(()),
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
                    ))
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
                    ))
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
                    ))
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
                    ))
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
                    ))
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
                    ))
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
                    ))
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
                        "Cannot access asset definition from a different domain. Asset definition domain: {}. Signers account domain {}.",
                        asset_definition_id.domain_id,
                        authority.domain_id
                    ))
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
                    ))
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
                    ))
                }
            }
            FindDomainById(query::FindDomainById { id })
            | FindDomainKeyValueByIdAndKey(query::FindDomainKeyValueByIdAndKey { id, .. }) => {
                let domain_id = id.evaluate(wsv, &context).map_err(|err| err.to_string())?;
                if domain_id == authority.domain_id {
                    Ok(())
                } else {
                    Err(format!("Cannot access a different domain: {}.", domain_id))
                }
            }
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
                    ))
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
                    ))
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
                    ))
                }
            }
        }
    }
}

impl_from_item_for_query_validator_box!(OnlyAccountsDomain);

/// Allow queries that only access the signers account data.
#[derive(Debug, Copy, Clone)]
pub struct OnlyAccountsData;

impl<W: WorldTrait> IsAllowed<W, QueryBox> for OnlyAccountsData {
    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn check(
        &self,
        authority: &AccountId,
        query: &QueryBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        use QueryBox::*;

        let context = Context::new();
        match query {
            FindAccountsByName(_)
            | FindAccountsByDomainId(_)
            | FindAllAccounts(_)
            | FindAllAssetsDefinitions(_)
            | FindAssetsByAssetDefinitionId(_)
            | FindAssetsByDomainId(_)
            | FindAssetsByName(_)
            | FindAllDomains(_)
            | FindDomainById(_)
            | FindDomainKeyValueByIdAndKey(_)
            | FindAssetsByDomainIdAndAssetDefinitionId(_)
            | FindAssetDefinitionKeyValueByIdAndKey(_)
            | FindAllAssets(_) => {
                Err("Only access to the assets of the same domain is permitted.".to_owned())
            }
            FindAllRoles(_) => Ok(()),
            FindAllPeers(_) => Ok(()),
            FindAccountById(query) => {
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
                    ))
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
                    ))
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
                    ))
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
                    ))
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
                    ))
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
                    ))
                }
            }

            FindTransactionsByAccountId(query) => {
                let account_id = query
                    .account_id
                    .evaluate(wsv, &context)
                    .map_err(|err| err.to_string())?;
                if &account_id == authority {
                    Ok(())
                } else {
                    Err(format!("Cannot access another account: {}.", account_id))
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
                    Err(format!("Cannot access another account: {}.", account_id))
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
                    Err(format!("Cannot access another account: {}.", account_id))
                }
            }
        }
    }
}

impl_from_item_for_query_validator_box!(OnlyAccountsData);
