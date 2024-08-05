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
        isi::error::{InstructionExecutionError, InvalidParameterError, RepetitionError},
        parameter::{CustomParameter, Parameter},
        prelude::*,
        query::error::FindError,
        Level,
    };
    use iroha_primitives::{json::JsonString, unique_vec::PushResult};

    use super::*;

    impl Execute for Register<Peer> {
        #[metrics(+"register_peer")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let peer_id = self.object.id;

            let world = &mut state_transaction.world;
            if let PushResult::Duplicate(duplicate) = world.trusted_peers_ids.push(peer_id.clone())
            {
                return Err(RepetitionError {
                    instruction: InstructionType::Register,
                    id: IdBox::PeerId(duplicate),
                }
                .into());
            }

            world.emit_events(Some(PeerEvent::Added(peer_id)));

            Ok(())
        }
    }

    impl Execute for Unregister<Peer> {
        #[metrics(+"unregister_peer")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let peer_id = self.object;
            let world = &mut state_transaction.world;
            let Some(index) = world.trusted_peers_ids.iter().position(|id| id == &peer_id) else {
                return Err(FindError::Peer(peer_id).into());
            };

            world.trusted_peers_ids.remove(index);

            world.emit_events(Some(PeerEvent::Removed(peer_id)));

            Ok(())
        }
    }

    impl Execute for Register<Domain> {
        #[metrics("register_domain")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain: Domain = self.object.build(authority);
            let domain_id = domain.id().clone();

            if domain_id == *iroha_genesis::GENESIS_DOMAIN_ID {
                return Err(InstructionExecutionError::InvariantViolation(
                    "Not allowed to register genesis domain".to_owned(),
                ));
            }

            let world = &mut state_transaction.world;
            if world.domains.get(&domain_id).is_some() {
                return Err(RepetitionError {
                    instruction: InstructionType::Register,
                    id: IdBox::DomainId(domain_id),
                }
                .into());
            }

            world.domains.insert(domain_id, domain.clone());
            world.emit_events(Some(DomainEvent::Created(domain)));

            Ok(())
        }
    }

    impl Execute for Unregister<Domain> {
        #[metrics("unregister_domain")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain_id = self.object;

            state_transaction
                .world()
                .triggers()
                .inspect_by_action(
                    |action| action.authority().domain() == &domain_id,
                    |trigger_id, _| trigger_id.clone(),
                )
                .collect::<Vec<_>>()
                .into_iter()
                .for_each(|trigger_id| {
                    state_transaction
                        .world
                        .triggers
                        .remove(trigger_id)
                        .then_some(())
                        .expect("should succeed")
                });

            let remove_accounts: Vec<AccountId> = state_transaction
                .world
                .accounts_in_domain_iter(&domain_id)
                .map(|account| account.id().clone())
                .collect();
            for account in remove_accounts {
                state_transaction
                    .world
                    .account_permissions
                    .remove(account.clone());

                state_transaction.world.remove_account_roles(&account);

                let remove_assets: Vec<AssetId> = state_transaction
                    .world
                    .assets_in_account_iter(&account)
                    .map(|ad| ad.id().clone())
                    .collect();
                for asset_id in remove_assets {
                    state_transaction.world.assets.remove(asset_id);
                }

                state_transaction.world.accounts.remove(account);
            }

            let remove_asset_definitions: Vec<AssetDefinitionId> = state_transaction
                .world
                .asset_definitions_in_domain_iter(&domain_id)
                .map(|ad| ad.id().clone())
                .collect();
            for asset_definition_id in remove_asset_definitions {
                state_transaction
                    .world
                    .asset_definitions
                    .remove(asset_definition_id.clone());
                state_transaction
                    .world
                    .asset_total_quantities
                    .remove(asset_definition_id);
            }

            if state_transaction
                .world
                .domains
                .remove(domain_id.clone())
                .is_none()
            {
                return Err(FindError::Domain(domain_id).into());
            }

            state_transaction
                .world
                .emit_events(Some(DomainEvent::Deleted(domain_id)));

            Ok(())
        }
    }

    impl Execute for Register<Role> {
        #[metrics(+"register_role")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role = self.object.build(authority);

            if state_transaction.world.roles.get(role.id()).is_some() {
                return Err(RepetitionError {
                    instruction: InstructionType::Register,
                    id: IdBox::RoleId(role.id),
                }
                .into());
            }

            let world = &mut state_transaction.world;
            let role_id = role.id().clone();
            world.roles.insert(role_id, role.clone());

            world.emit_events(Some(RoleEvent::Created(role)));

            Ok(())
        }
    }

    impl Execute for Unregister<Role> {
        #[metrics("unregister_role")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role_id = self.object;

            let accounts_with_role = state_transaction
                .world
                .account_roles
                .iter()
                .map(|(role, ())| role)
                .filter(|role| role.id.eq(&role_id))
                .map(|role| &role.account)
                .cloned()
                .collect::<Vec<_>>();

            for account_id in accounts_with_role {
                let revoke = Revoke {
                    object: role_id.clone(),
                    destination: account_id,
                };
                revoke.execute(authority, state_transaction)?
            }

            let world = &mut state_transaction.world;
            if world.roles.remove(role_id.clone()).is_none() {
                return Err(FindError::Role(role_id).into());
            }

            world.emit_events(Some(RoleEvent::Deleted(role_id)));

            Ok(())
        }
    }

    impl Execute for Grant<Permission, Role> {
        #[metrics(+"grant_role_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role_id = self.destination;
            let permission = self.object;

            let Some(role) = state_transaction.world.roles.get_mut(&role_id) else {
                return Err(FindError::Role(role_id).into());
            };

            if !role.permissions.insert(permission.clone()) {
                return Err(RepetitionError {
                    instruction: InstructionType::Grant,
                    id: permission.into(),
                }
                .into());
            }

            state_transaction
                .world
                .emit_events(Some(RoleEvent::PermissionAdded(RolePermissionChanged {
                    role: role_id,
                    permission,
                })));

            Ok(())
        }
    }

    impl Execute for Revoke<Permission, Role> {
        #[metrics(+"grant_role_permission")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let role_id = self.destination;
            let permission = self.object;

            let Some(role) = state_transaction.world.roles.get_mut(&role_id) else {
                return Err(FindError::Role(role_id).into());
            };

            if !role.permissions.remove(&permission) {
                return Err(FindError::Permission(permission).into());
            }

            state_transaction
                .world
                .emit_events(Some(RoleEvent::PermissionRemoved(RolePermissionChanged {
                    role: role_id,
                    permission,
                })));

            Ok(())
        }
    }

    impl Execute for SetParameter {
        #[metrics(+"set_parameter")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            macro_rules! set_parameter {
                ($($container:ident($param:ident.$field:ident) => $single:ident::$variant:ident),* $(,)?) => {
                    match self.0 { $(
                        Parameter::$container(iroha_data_model::parameter::$single::$variant(next)) => {
                            let prev = core::mem::replace(
                                &mut state_transaction.world.parameters.$param.$field,
                                next,
                            );

                            state_transaction.world.emit_events(
                                Some(ConfigurationEvent::Changed(ParameterChanged {
                                    old_value: Parameter::$container(iroha_data_model::parameter::$single::$variant(
                                        prev,
                                    )),
                                    new_value: Parameter::$container(iroha_data_model::parameter::$single::$variant(
                                        next,
                                    )),
                                }))
                            );
                        })*
                        Parameter::Custom(next) => {
                            let prev = state_transaction
                                .world
                                .parameters
                                .custom
                                .insert(next.id.clone(), next.clone())
                                .unwrap_or_else(|| {
                                    iroha_logger::error!(
                                        "{}: Initial parameter value not set during executor migration",
                                        next.id
                                    );

                                    CustomParameter {
                                        id: next.id.clone(),
                                        payload: JsonString::default(),
                                    }
                                });

                            state_transaction
                                .world
                                .emit_events(Some(ConfigurationEvent::Changed(ParameterChanged {
                                    old_value: Parameter::Custom(prev),
                                    new_value: Parameter::Custom(next),
                                })));
                        }
                    }
                };
            }

            set_parameter!(
                Sumeragi(sumeragi.block_time_ms) => SumeragiParameter::BlockTimeMs,
                Sumeragi(sumeragi.commit_time_ms) => SumeragiParameter::CommitTimeMs,

                Block(block.max_transactions) => BlockParameter::MaxTransactions,

                Transaction(transaction.max_instructions) => TransactionParameter::MaxInstructions,
                Transaction(transaction.smart_contract_size) => TransactionParameter::SmartContractSize,

                SmartContract(smart_contract.fuel) => SmartContractParameter::Fuel,
                SmartContract(smart_contract.memory) => SmartContractParameter::Memory,

                Executor(executor.fuel) => SmartContractParameter::Fuel,
                Executor(executor.memory) => SmartContractParameter::Memory,
            );

            Ok(())
        }
    }

    impl Execute for Upgrade {
        #[metrics(+"upgrade_executor")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let raw_executor = self.executor;

            // Cloning executor to avoid multiple mutable borrows of `state_transaction`.
            // Also it's a cheap operation.
            let mut upgraded_executor = state_transaction.world.executor.clone();
            upgraded_executor
                .migrate(raw_executor, state_transaction, authority)
                .map_err(|migration_error| {
                    InvalidParameterError::Wasm(format!(
                        "{:?}",
                        eyre::eyre!(migration_error).wrap_err("Migration failed"),
                    ))
                })?;

            *state_transaction.world.executor.get_mut() = upgraded_executor;

            state_transaction
                .world
                .emit_events(std::iter::once(ExecutorEvent::Upgraded(ExecutorUpgrade {
                    new_data_model: state_transaction.world.executor_data_model.clone(),
                })));

            Ok(())
        }
    }

    impl Execute for Log {
        fn execute(
            self,
            _authority: &AccountId,
            _state_transaction: &mut StateTransaction<'_, '_>,
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
        parameter::Parameters,
        peer::Peer,
        prelude::*,
        query::{
            error::QueryExecutionFail as Error,
            predicate::{
                predicate_atoms::{
                    peer::PeerPredicateBox,
                    role::{RoleIdPredicateBox, RolePredicateBox},
                },
                CompoundPredicate,
            },
        },
        role::Role,
    };

    use super::*;
    use crate::{smartcontracts::ValidQuery, state::StateReadOnly};

    impl ValidQuery for FindRoles {
        #[metrics(+"find_roles")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<RolePredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Self::Item> + 'state, Error> {
            Ok(state_ro
                .world()
                .roles()
                .iter()
                .map(|(_, role)| role)
                .filter(move |&role| filter.applies(role))
                .cloned())
        }
    }

    impl ValidQuery for FindRoleIds {
        #[metrics(+"find_role_ids")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<RoleIdPredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Self::Item> + 'state, Error> {
            Ok(state_ro
                .world()
                .roles()
                .iter()
                .map(|(_, role)| role)
                .map(Role::id)
                .filter(move |&role| filter.applies(role))
                .cloned())
        }
    }

    impl ValidQuery for FindPeers {
        #[metrics(+"find_peers")]
        fn execute<'state>(
            self,
            filter: CompoundPredicate<PeerPredicateBox>,
            state_ro: &'state impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Self::Item> + 'state, Error> {
            Ok(state_ro
                .world()
                .peers()
                .cloned()
                .map(Peer::new)
                .filter(move |peer| filter.applies(peer)))
        }
    }

    impl ValidSingularQuery for FindExecutorDataModel {
        #[metrics(+"find_executor_data_model")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<ExecutorDataModel, Error> {
            Ok(state_ro.world().executor_data_model().clone())
        }
    }

    impl ValidSingularQuery for FindParameters {
        #[metrics(+"find_parameters")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Parameters, Error> {
            Ok(state_ro.world().parameters().clone())
        }
    }
}
