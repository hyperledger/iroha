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
    use eyre::Result;
    use iroha_data_model::{
        isi::error::{InvalidParameterError, RepetitionError},
        prelude::*,
        query::error::FindError,
        Level,
    };

    use super::*;

    impl Execute for Register<Peer> {
        #[metrics(+"register_peer")]
        fn execute(self, _authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let peer_id = self.object.id;

            let world = wsv.world_mut();
            if !world.trusted_peers_ids.push(peer_id.clone()) {
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
            let Some(index) = world.trusted_peers_ids.iter().position(|id| id == &peer_id) else {
                return Err(FindError::Peer(peer_id).into());
            };

            world.trusted_peers_ids.remove(index);

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
                .validate_len(wsv.config.identifier_length_limits)
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

            if wsv.roles().contains_key(role.id()) {
                return Err(RepetitionError {
                    instruction_type: InstructionType::Register,
                    id: IdBox::RoleId(role.id),
                }
                .into());
            }

            for permission in &role.permissions {
                if !wsv
                    .permission_token_schema()
                    .token_ids
                    .contains(&permission.definition_id)
                {
                    return Err(FindError::PermissionToken(permission.definition_id.clone()).into());
                }
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

            let accounts_with_role = wsv
                .world
                .account_roles
                .iter()
                .filter(|role| role.role_id.eq(&role_id))
                .map(|role| &role.account_id)
                .cloned()
                .collect::<Vec<_>>();

            for account_id in accounts_with_role {
                let revoke = Revoke {
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

    impl Execute for Upgrade {
        #[metrics(+"upgrade_executor")]
        fn execute(self, authority: &AccountId, wsv: &mut WorldStateView) -> Result<(), Error> {
            let raw_executor = self.executor;

            // Cloning executor to avoid multiple mutable borrows of `wsv`.
            // Also it's a cheap operation.
            let mut upgraded_executor = wsv.executor().clone();
            upgraded_executor
                .migrate(raw_executor, wsv, authority)
                .map_err(|migration_error| {
                    InvalidParameterError::Wasm(format!(
                        "{:?}",
                        eyre::eyre!(migration_error).wrap_err("Migration failed"),
                    ))
                })?;

            wsv.world_mut().executor = upgraded_executor;

            wsv.emit_events(std::iter::once(ExecutorEvent::Upgraded));

            Ok(())
        }
    }

    impl Execute for Log {
        fn execute(
            self,
            _authority: &AccountId,
            _wsv: &mut WorldStateView,
        ) -> std::result::Result<(), Error> {
            const TARGET: &str = "log_isi";
            let Self { level, msg } = self;

            match level {
                Level::TRACE => iroha_logger::trace!(target: TARGET, "{}", msg),
                Level::DEBUG => iroha_logger::debug!(target: TARGET, "{}", msg),
                Level::INFO => iroha_logger::info!(target: TARGET, "{}", msg),
                Level::WARN => iroha_logger::warn!(target: TARGET, "{}", msg),
                Level::ERROR => iroha_logger::error!(target: TARGET, "{}", msg),
            }

            Ok(())
        }
    }
}
/// Query module provides `IrohaQuery` Peer related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        parameter::Parameter,
        peer::Peer,
        permission::PermissionTokenSchema,
        prelude::*,
        query::error::{FindError, QueryExecutionFail as Error},
        role::{Role, RoleId},
    };

    use super::*;

    impl ValidQuery for FindAllRoles {
        #[metrics(+"find_all_roles")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Role> + 'wsv>, Error> {
            Ok(Box::new(wsv.world.roles.values().cloned()))
        }
    }

    impl ValidQuery for FindAllRoleIds {
        #[metrics(+"find_all_role_ids")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = RoleId> + 'wsv>, Error> {
            Ok(Box::new(wsv
               .world
               .roles
               .values()
               // To me, this should probably be a method, not a field.
               .map(Role::id)
               .cloned()))
        }
    }

    impl ValidQuery for FindRoleByRoleId {
        #[metrics(+"find_role_by_role_id")]
        fn execute(&self, wsv: &WorldStateView) -> Result<Role, Error> {
            let role_id = &self.id;
            iroha_logger::trace!(%role_id);

            wsv.world.roles.get(role_id).map_or_else(
                || Err(Error::Find(FindError::Role(role_id.clone()))),
                |role_ref| Ok(role_ref.clone()),
            )
        }
    }

    impl ValidQuery for FindAllPeers {
        #[metrics("find_all_peers")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Peer> + 'wsv>, Error> {
            Ok(Box::new(wsv.peers().cloned().map(Peer::new)))
        }
    }

    impl ValidQuery for FindPermissionTokenSchema {
        #[metrics("find_permission_token_schema")]
        fn execute(&self, wsv: &WorldStateView) -> Result<PermissionTokenSchema, Error> {
            Ok(wsv.permission_token_schema().clone())
        }
    }

    impl ValidQuery for FindAllParameters {
        #[metrics("find_all_parameters")]
        fn execute<'wsv>(
            &self,
            wsv: &'wsv WorldStateView,
        ) -> Result<Box<dyn Iterator<Item = Parameter> + 'wsv>, Error> {
            Ok(Box::new(wsv.parameters().cloned()))
        }
    }
}
