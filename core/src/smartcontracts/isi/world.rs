//! `World`-related ISI implementations.

use iroha_telemetry::metrics;

use super::prelude::*;
use crate::prelude::*;

impl Registrable for NewRole {
    type Target = Role;

    #[must_use]
    #[inline]
    fn build(self, _authority: AccountId) -> Self::Target {
        self.inner
    }
}

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use eyre::Result;
    use iroha_data_model::{prelude::*, query::error::FindError};

    use super::*;

    impl Execute for Register<Peer> {
        type Error = Error;

        #[metrics(+"register_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let peer_id = self.object.id;

            wsv.modify_world(|world| {
                if !world.trusted_peers_ids.insert(peer_id.clone()) {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::PeerId(peer_id),
                    ));
                }

                Ok(PeerEvent::Added(peer_id).into())
            })
        }
    }

    impl Execute for Unregister<Peer> {
        type Error = Error;

        #[metrics(+"unregister_peer")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let peer_id = self.object_id;
            wsv.modify_world(|world| {
                if world.trusted_peers_ids.remove(&peer_id).is_none() {
                    return Err(FindError::Peer(peer_id).into());
                }

                Ok(PeerEvent::Removed(peer_id).into())
            })
        }
    }

    impl Execute for Register<Domain> {
        type Error = Error;

        #[metrics("register_domain")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let domain: Domain = self.object.build(authority);
            let domain_id = domain.id().clone();

            domain_id
                .name
                .validate_len(wsv.config.borrow().ident_length_limits)
                .map_err(Error::from)?;

            wsv.modify_world(|world| {
                if world.domains.contains_key(&domain_id) {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::DomainId(domain_id),
                    ));
                }

                world.domains.insert(domain_id.clone(), domain.clone());
                Ok(DomainEvent::Created(domain).into())
            })?;

            Ok(())
        }
    }

    impl Execute for Unregister<Domain> {
        type Error = Error;

        #[metrics("unregister_domain")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let domain_id = self.object_id;

            wsv.modify_world(|world| {
                if world.domains.remove(&domain_id).is_none() {
                    return Err(FindError::Domain(domain_id).into());
                }

                Ok(DomainEvent::Deleted(domain_id).into())
            })?;

            Ok(())
        }
    }

    impl Execute for Register<Role> {
        type Error = Error;

        #[metrics(+"register_role")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let role = self.object.build(authority);

            for permission in &role.permissions {
                let definition = wsv
                    .permission_token_definitions()
                    .get(&permission.definition_id)
                    .ok_or_else(|| {
                        FindError::PermissionTokenDefinition(permission.definition_id.clone())
                    })?;

                permissions::check_permission_token_parameters(permission, definition.value())?;
            }

            if wsv.roles().contains_key(role.id()) {
                return Err(Error::Repetition(
                    InstructionType::Register,
                    IdBox::RoleId(role.id),
                ));
            }

            wsv.modify_world(|world| {
                let role_id = role.id().clone();
                world.roles.insert(role_id, role.clone());
                Ok(RoleEvent::Created(role).into())
            })
        }
    }

    impl Execute for Unregister<Role> {
        type Error = Error;

        #[metrics("unregister_role")]
        fn execute(
            self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let role_id = self.object_id;

            let mut accounts_with_role = vec![];
            for domain in wsv.domains().iter() {
                let account_ids = domain.accounts.values().filter_map(|account| {
                    if account.roles.contains(&role_id) {
                        return Some(account.id().clone());
                    }

                    None
                });

                accounts_with_role.extend(account_ids);
            }

            for account_id in accounts_with_role {
                let revoke: Revoke<Account, RoleId> = Revoke {
                    object: role_id.clone(),
                    destination_id: account_id,
                };
                revoke.execute(authority.clone(), wsv)?
            }

            wsv.modify_world(|world| {
                if world.roles.remove(&role_id).is_none() {
                    return Err(FindError::Role(role_id).into());
                }

                Ok(RoleEvent::Deleted(role_id).into())
            })
        }
    }

    impl Execute for Register<PermissionTokenDefinition> {
        type Error = Error;

        #[metrics(+"register_token")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let definition = self.object;
            let definition_id = definition.id().clone();

            wsv.modify_world(|world| {
                if world
                    .permission_token_definitions
                    .contains_key(&definition_id)
                {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::PermissionTokenDefinitionId(definition_id),
                    ));
                }

                world
                    .permission_token_definitions
                    .insert(definition_id, definition.clone());
                Ok(PermissionTokenEvent::DefinitionCreated(definition).into())
            })
        }
    }

    impl Execute for Unregister<PermissionTokenDefinition> {
        type Error = Error;

        #[metrics("unregister_permission_token")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let definition_id = self.object_id;

            remove_token_from_roles(wsv, &definition_id)?;
            remove_token_from_accounts(wsv, &definition_id)?;

            wsv.modify_world(|world| {
                match world.permission_token_definitions.remove(&definition_id) {
                    Some((_, definition)) => {
                        Ok(PermissionTokenEvent::DefinitionDeleted(definition).into())
                    }
                    None => Err(FindError::PermissionTokenDefinition(definition_id).into()),
                }
            })?;

            Ok(())
        }
    }

    /// Remove all tokens with specified definition id from all registered roles
    fn remove_token_from_roles(
        wsv: &WorldStateView,
        target_definition_id: &<PermissionTokenDefinition as Identifiable>::Id,
    ) -> Result<(), Error> {
        let mut roles_containing_token = Vec::new();

        for role_entry in wsv.roles().iter() {
            let (role_id, role) = role_entry.pair();
            if role
                .permissions
                .iter()
                .any(|token| token.definition_id == *target_definition_id)
            {
                roles_containing_token.push(role_id.clone())
            }
        }

        for role_id in roles_containing_token {
            wsv.modify_world(|world| {
                if let Some(mut role) = world.roles.get_mut(&role_id) {
                    role.permissions
                        .retain(|token| token.definition_id != *target_definition_id);
                    Ok(RoleEvent::PermissionRemoved(PermissionRemoved {
                        role_id,
                        permission_definition_id: target_definition_id.clone(),
                    })
                    .into())
                } else {
                    error!(%role_id, "role not found. This is a bug");
                    Err(FindError::Role(role_id.clone()).into())
                }
            })?;
        }

        Ok(())
    }

    /// Remove all tokens with specified definition id from all accounts in all domains
    fn remove_token_from_accounts(
        wsv: &WorldStateView,
        target_definition_id: &<PermissionTokenDefinition as Identifiable>::Id,
    ) -> Result<(), Error> {
        let mut accounts_with_token = std::collections::HashMap::new();

        for domain in wsv.domains().iter() {
            let account_ids = domain.accounts.values().map(|account| {
                (
                    account.id().clone(),
                    wsv.account_inherent_permission_tokens(account)
                        .filter(|token| token.definition_id == *target_definition_id)
                        .collect::<Vec<_>>(),
                )
            });

            accounts_with_token.extend(account_ids);
        }

        for (account_id, tokens) in accounts_with_token {
            for token in tokens {
                wsv.modify_account(&account_id, |account| {
                    let id = account.id();
                    if !wsv.remove_account_permission(id, &token) {
                        error!(%token, "token not found. This is a bug");
                    }

                    Ok(AccountEvent::PermissionRemoved(AccountPermissionChanged {
                        account_id: id.clone(),
                        permission_id: token.definition_id,
                    }))
                })?;
            }
        }
        Ok(())
    }

    impl Execute for SetParameter {
        type Error = Error;

        #[metrics(+"set_parameter")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let parameter = self.parameter;

            wsv.modify_world(|world| {
                if world.parameters.remove(&parameter).is_some() {
                    world.parameters.insert(parameter.clone());
                    Ok(ConfigurationEvent::Changed(parameter.id).into())
                } else {
                    Err(FindError::Parameter(parameter.id).into())
                }
            })
        }
    }

    impl Execute for NewParameter {
        type Error = Error;

        #[metrics(+"new_parameter")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let parameter = self.parameter;

            wsv.modify_world(|world| {
                if world.parameters.insert(parameter.clone()) {
                    Ok(ConfigurationEvent::Created(parameter.id).into())
                } else {
                    Err(Error::Repetition(
                        InstructionType::NewParameter,
                        IdBox::ParameterId(parameter.id),
                    ))
                }
            })
        }
    }

    impl Execute for Upgrade<Validator> {
        type Error = Error;

        #[metrics(+"upgrade_validator")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            #[cfg(test)]
            use crate::validator::MockValidator as Validator;
            #[cfg(not(test))]
            use crate::validator::Validator;

            let raw_validator = self.object;
            wsv.modify_world(|world| {
                let new_validator = Validator::new(raw_validator).map_err(|err| {
                    ValidationError::new(format!("Failed to load wasm blob: {err}"))
                })?;
                let _ = world.upgraded_validator.write().insert(new_validator);
                Ok(ValidatorEvent::Upgraded.into())
            })
        }
    }
}
/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        prelude::*,
        query::{
            error::{FindError, QueryExecutionFailure as Error},
            permission::DoesAccountHavePermissionToken,
        },
    };

    use super::*;

    impl ValidQuery for FindAllRoles {
        #[metrics(+"find_all_roles")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv
                .world
                .roles
                .iter()
                .map(|role| role.value().clone())
                .collect())
        }
    }

    impl ValidQuery for FindAllRoleIds {
        #[metrics(+"find_all_role_ids")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv
               .world
               .roles
               .iter()
               // To me, this should probably be a method, not a field.
               .map(|role| role.id().clone())
               .collect())
        }
    }

    impl ValidQuery for FindRoleByRoleId {
        #[metrics(+"find_role_by_role_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let role_id = self
                .id
                .evaluate(&Context::new(wsv))
                .map_err(|e| Error::Evaluate(e.to_string()))?;
            iroha_logger::trace!(%role_id);

            wsv.world.roles.get(&role_id).map_or_else(
                || Err(Error::Find(Box::new(FindError::Role(role_id)))),
                |role_ref| Ok(role_ref.clone()),
            )
        }
    }

    impl ValidQuery for FindAllPeers {
        #[metrics("find_all_peers")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv.peers())
        }
    }

    impl ValidQuery for FindAllPermissionTokenDefinitions {
        #[metrics("find_all_token_ids")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv
                .permission_token_definitions()
                .iter()
                // Can't use `.cloned()` since `token_definition` here is a
                // `dashmap::mapref::multiple::RefMulti`, not a vanilla Rust reference
                .map(|token_definition| token_definition.clone())
                .collect())
        }
    }

    impl ValidQuery for FindAllParameters {
        #[metrics("find_all_parameters")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv.parameters())
        }
    }

    impl ValidQuery for DoesAccountHavePermissionToken {
        #[metrics("does_account_have_permission")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let account_id = self
                .account_id
                .evaluate(&Context::new(wsv))
                .map_err(|e| Error::Evaluate(e.to_string()))?;

            wsv.map_account(&account_id, |account| {
                wsv.account_permission_tokens(account)
                    .contains(&self.permission_token)
            })
        }
    }
}
