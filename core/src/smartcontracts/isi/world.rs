//! `World`-related ISI implementations.

use iroha_telemetry::metrics;

use super::prelude::*;
use crate::prelude::*;

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use eyre::Result;
    use iroha_data_model::prelude::*;

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
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let domain: Domain = self.object.build();
            let domain_id = domain.id().clone();

            domain_id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::Validate)?;

            wsv.modify_world(|world| {
                if world.domains.contains_key(&domain_id) {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::DomainId(domain_id),
                    ));
                }

                world.domains.insert(domain_id.clone(), domain);
                Ok(DomainEvent::Created(domain_id).into())
            })?;

            wsv.metrics.domains.inc();
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

            wsv.metrics.domains.dec();
            Ok(())
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

    impl Execute for Register<Role> {
        type Error = Error;

        #[metrics(+"register_role")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let role = self.object.build();

            wsv.modify_world(|world| {
                let role_id = role.id().clone();

                for token_definition_id in role.permissions().map(PermissionToken::definition_id) {
                    if !world
                        .permission_token_definitions
                        .contains_key(token_definition_id)
                    {
                        return Err(Error::Find(Box::new(FindError::PermissionTokenDefinition(
                            token_definition_id.clone(),
                        ))));
                    }
                }

                if world.roles.contains_key(&role_id) {
                    return Err(Error::Repetition(
                        InstructionType::Register,
                        IdBox::RoleId(role_id),
                    ));
                }

                world.roles.insert(role_id.clone(), role);
                Ok(RoleEvent::Created(role_id).into())
            })
        }
    }

    impl Execute for Unregister<Role> {
        type Error = Error;

        #[metrics("unregister_role")]
        fn execute(
            self,
            _authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), Self::Error> {
            let role_id = self.object_id;

            let mut accounts_with_role = vec![];
            for domain in wsv.domains().iter() {
                let account_ids = domain.accounts().filter_map(|account| {
                    if account.contains_role(&role_id) {
                        return Some(account.id().clone());
                    }

                    None
                });

                accounts_with_role.extend(account_ids);
            }

            for account_id in accounts_with_role {
                wsv.modify_account(&account_id.clone(), |account| {
                    if !account.remove_role(&role_id) {
                        error!(%role_id, "role not found - this is a bug");
                    }

                    Ok(AccountEvent::RoleRevoked(account_id))
                })?;
            }

            wsv.modify_world(|world| {
                if world.roles.remove(&role_id).is_none() {
                    return Err(FindError::Role(role_id).into());
                }

                Ok(RoleEvent::Deleted(role_id).into())
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
                .permissions()
                .any(|token| token.definition_id() == target_definition_id)
            {
                roles_containing_token.push(role_id.clone())
            }
        }

        for role_id in roles_containing_token {
            wsv.modify_world(|world| {
                if let Some(mut role) = world.roles.get_mut(&role_id) {
                    role.remove_permissions(target_definition_id);
                    Ok(RoleEvent::PermissionRemoved(PermissionRemoved {
                        role_id,
                        permission_definition_id: target_definition_id.clone(),
                    })
                    .into())
                } else {
                    error!(%role_id, "role not found - this is a bug");
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
            let account_ids = domain.accounts().map(|account| {
                (
                    account.id().clone(),
                    wsv.account_inherent_permission_tokens(account)
                        .filter(|token| token.definition_id() == target_definition_id)
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
                        error!(%token, "token not found - this is a bug");
                    }

                    Ok(AccountEvent::PermissionRemoved(id.clone()))
                })?;
            }
        }
        Ok(())
    }
}

/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::prelude::*;

    use super::*;
    use crate::smartcontracts::query::Error;

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
                .evaluate(wsv, &Context::new())
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
}
