//! `World`-related ISI implementations.

use iroha_telemetry::metrics;

use super::prelude::*;
use crate::prelude::*;

impl Registrable for NewRole {
    type Target = Role;

    #[must_use]
    #[inline]
    fn build(self, _authority: &AccountId) -> Self::Target {
        self.inner
    }
}

/// Iroha Special Instructions that have `World` as their target.
pub mod isi {
    use std::collections::HashSet;

    use eyre::Result;
    use iroha_data_model::{
        isi::error::{InvalidParameterError, RepetitionError},
        prelude::*,
        query::error::FindError,
    };

    use super::*;

    impl Execute for Register<Peer> {
        #[metrics(+"register_peer")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let peer_id = self.object.id;

            let world = wsv.world_mut();
            if !world.trusted_peers_ids.insert(peer_id.clone()) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::PeerId(peer_id),
                }
                .into());
            }

            wsv.emit_events(Some(PeerEvent::Added(peer_id)));

            Ok(())
        }
    }

    impl Execute for Unregister<Peer> {
        #[metrics(+"unregister_peer")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let peer_id = self.object_id;
            let world = wsv.world_mut();
            if !world.trusted_peers_ids.remove(&peer_id) {
                return Err(FindError::Peer(peer_id).into());
            }

            wsv.emit_events(Some(PeerEvent::Removed(peer_id)));

            Ok(())
        }
    }

    impl Execute for Register<Domain> {
        #[metrics("register_domain")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let domain: Domain = self.object.build(authority);
            let domain_id = domain.id().clone();

            domain_id
                .name
                .validate_len(wsv.config.ident_length_limits)
                .map_err(Error::from)?;

            let world = wsv.world_mut();
            if world.domains.contains_key(&domain_id) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::DomainId(domain_id),
                }
                .into());
            }

            world.domains.insert(domain_id, domain.clone());

            wsv.emit_events(Some(DomainEvent::Created(domain)));

            Ok(())
        }
    }

    impl Execute for Unregister<Domain> {
        #[metrics("unregister_domain")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let domain_id = self.object_id;

            let world = wsv.world_mut();
            if world.domains.remove(&domain_id).is_none() {
                return Err(FindError::Domain(domain_id).into());
            }

            wsv.emit_events(Some(DomainEvent::Deleted(domain_id)));

            Ok(())
        }
    }

    impl Execute for Register<Role> {
        #[metrics(+"register_role")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let role = self.object.build(authority);

            for permission in &role.permissions {
                let definition = wsv
                    .permission_token_definitions()
                    .get(&permission.definition_id)
                    .ok_or_else(|| {
                        FindError::PermissionTokenDefinition(permission.definition_id.clone())
                    })?;

                permissions::check_permission_token_parameters(permission, definition)?;
            }

            if wsv.roles().contains_key(role.id()) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::RoleId(role.id),
                }
                .into());
            }

            let world = wsv.world_mut();
            let role_id = role.id().clone();
            world.roles.insert(role_id, role.clone());

            wsv.emit_events(Some(RoleEvent::Created(role)));

            Ok(())
        }
    }

    impl Execute for Unregister<Role> {
        #[metrics("unregister_role")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let role_id = self.object_id;

            let mut accounts_with_role = vec![];
            for domain in wsv.domains().values() {
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
                revoke.execute(authority, wsv)?
            }

            let world = wsv.world_mut();
            if world.roles.remove(&role_id).is_none() {
                return Err(FindError::Role(role_id).into());
            }

            wsv.emit_events(Some(RoleEvent::Deleted(role_id)));

            Ok(())
        }
    }

    impl Execute for Register<PermissionTokenDefinition> {
        #[metrics(+"register_token")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let definition = self.object;
            let definition_id = definition.id().clone();

            let world = wsv.world_mut();
            if world
                .permission_token_definitions
                .contains_key(&definition_id)
            {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::PermissionTokenDefinitionId(definition_id),
                }
                .into());
            }

            world
                .permission_token_definitions
                .insert(definition_id, definition.clone());

            wsv.emit_events(Some(PermissionTokenEvent::DefinitionCreated(definition)));

            Ok(())
        }
    }

    impl Execute for Unregister<PermissionTokenDefinition> {
        #[metrics("unregister_permission_token")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let definition_id = self.object_id;

            remove_token_from_roles(wsv, &definition_id)?;
            remove_token_from_accounts(wsv, &definition_id)?;

            let world = wsv.world_mut();
            let definition = world
                .permission_token_definitions
                .remove(&definition_id)
                .ok_or_else(|| FindError::PermissionTokenDefinition(definition_id))?;

            wsv.emit_events(Some(PermissionTokenEvent::DefinitionDeleted(definition)));

            Ok(())
        }
    }

    /// Remove all tokens with specified definition id from all registered roles
    fn remove_token_from_roles(
        wsv: &mut WorldStateView,
        target_definition_id: &<PermissionTokenDefinition as Identifiable>::Id,
    ) -> Result<(), Error> {
        let mut roles_containing_token = Vec::new();

        for (role_id, role) in wsv.roles().iter() {
            if role
                .permissions
                .iter()
                .any(|token| token.definition_id == *target_definition_id)
            {
                roles_containing_token.push(role_id.clone())
            }
        }

        let mut events = Vec::with_capacity(roles_containing_token.len());
        let world = wsv.world_mut();
        for role_id in roles_containing_token {
            if let Some(role) = world.roles.get_mut(&role_id) {
                role.permissions
                    .retain(|token| token.definition_id != *target_definition_id);
                events.push(RoleEvent::PermissionRemoved(PermissionRemoved {
                    role_id: role_id.clone(),
                    permission_definition_id: target_definition_id.clone(),
                }));
            } else {
                error!(%role_id, "role not found. This is a bug");
                return Err(FindError::Role(role_id.clone()).into());
            }
        }

        wsv.emit_events(events);

        Ok(())
    }

    /// Remove all tokens with specified definition id from all accounts in all domains
    fn remove_token_from_accounts(
        wsv: &mut WorldStateView,
        target_definition_id: &<PermissionTokenDefinition as Identifiable>::Id,
    ) -> Result<(), Error> {
        let mut accounts_with_token = std::collections::HashMap::new();

        for domain in wsv.domains().values() {
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

        let mut events = Vec::new();
        for (account_id, tokens) in accounts_with_token {
            for token in tokens {
                if !wsv.remove_account_permission(&account_id, &token) {
                    error!(%token, "token not found. This is a bug");
                    return Err(
                        FindError::PermissionTokenDefinition(token.definition_id.clone()).into(),
                    );
                }
                events.push(AccountEvent::PermissionRemoved(AccountPermissionChanged {
                    account_id: account_id.clone(),
                    permission_id: token.definition_id,
                }));
            }
        }
        wsv.emit_events(events);

        Ok(())
    }

    impl Execute for SetParameter {
        #[metrics(+"set_parameter")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let parameter = self.parameter;
            let parameter_id = parameter.id.clone();

            let world = wsv.world_mut();
            if !world.parameters.remove(&parameter) {
                return Err(FindError::Parameter(parameter_id).into());
            }

            world.parameters.insert(parameter);

            wsv.emit_events(Some(ConfigurationEvent::Changed(parameter_id)));

            Ok(())
        }
    }

    impl Execute for NewParameter {
        #[metrics(+"new_parameter")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let parameter = self.parameter;
            let parameter_id = parameter.id.clone();

            let world = wsv.world_mut();
            if !world.parameters.insert(parameter) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::NewParameter,
                    id: IdBox::ParameterId(parameter_id),
                }
                .into());
            }

            wsv.emit_events(Some(ConfigurationEvent::Created(parameter_id)));

            Ok(())
        }
    }

    impl Execute for Upgrade<Validator> {
        #[metrics(+"upgrade_validator")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            #[cfg(test)]
            use crate::validator::MockValidator as Validator;
            #[cfg(not(test))]
            use crate::validator::Validator;

            let raw_validator = self.object;
            let engine = wsv.engine.clone(); // Cloning engine is cheap

            let (new_validator, new_permission_token_definitions) =
                || -> Result<_, crate::smartcontracts::wasm::error::Error> {
                    {
                        let new_validator = Validator::new(raw_validator, &engine)?;
                        let new_permission_token_definitions =
                            new_validator.permission_tokens(wsv)?;
                        Ok((new_validator, new_permission_token_definitions))
                    }
                }()
                .map_err(|error| {
                    InvalidParameterError::Wasm(format!("{:?}", eyre::Report::from(error)))
                })?;

            let world = wsv.world_mut();
            let _ = world.upgraded_validator.insert(new_validator);

            let old_permission_token_definitions = wsv
                .permission_token_definitions()
                .values()
                .cloned()
                .collect::<HashSet<_>>();
            let new_permission_token_definitions =
                HashSet::from_iter(new_permission_token_definitions);

            old_permission_token_definitions
                .difference(&new_permission_token_definitions)
                .map(|definition| Unregister::<PermissionTokenDefinition> {
                    object_id: definition.id.clone(),
                })
                .try_for_each(|unregister| unregister.execute(authority, wsv))?;

            new_permission_token_definitions
                .difference(&old_permission_token_definitions)
                .cloned()
                .map(|definition| Register::<PermissionTokenDefinition> { object: definition })
                .try_for_each(|new| new.execute(authority, wsv))?;

            wsv.emit_events(Some(ValidatorEvent::Upgraded));

            Ok(())
        }
    }
}
/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        prelude::*,
        query::{
            error::{FindError, QueryExecutionFail as Error},
            permission::DoesAccountHavePermissionToken,
        },
    };

    use super::*;

    impl ValidQuery for FindAllRoles {
        #[metrics(+"find_all_roles")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv.world.roles.values().cloned().collect())
        }
    }

    impl ValidQuery for FindAllRoleIds {
        #[metrics(+"find_all_role_ids")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            Ok(wsv
               .world
               .roles
               .values()
               // To me, this should probably be a method, not a field.
               .map(Role::id)
               .cloned()
               .collect())
        }
    }

    impl ValidQuery for FindRoleByRoleId {
        #[metrics(+"find_role_by_role_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
            let role_id = wsv
                .evaluate(&self.id)
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
                .values()
                .cloned()
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
            let authority = wsv
                .evaluate(&self.account_id)
                .map_err(|e| Error::Evaluate(e.to_string()))?;

            wsv.map_account(&authority, |account| {
                wsv.account_permission_tokens(account)
                    .contains(&self.permission_token)
            })
        }
    }
}
