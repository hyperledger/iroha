//! This module contains [`Domain`] structure and related implementations and trait implementations.

use eyre::Result;
use iroha_data_model::{prelude::*, query::error::FindError};
use iroha_telemetry::metrics;

use crate::smartcontracts::isi::prelude::*;

impl Registrable for iroha_data_model::domain::NewDomain {
    type Target = Domain;

    #[must_use]
    #[inline]
    fn build(self, authority: &AccountId) -> Self::Target {
        Self::Target {
            id: self.id,
            metadata: self.metadata,
            logo: self.logo,
            owned_by: authority.clone(),
        }
    }
}

/// ISI module contains all instructions related to domains:
/// - creating/changing assets
/// - registering/unregistering accounts
/// - update metadata
/// - transfer, etc.
pub mod isi {
    use iroha_data_model::isi::error::{InstructionExecutionError, RepetitionError};

    use super::*;

    impl Execute for Register<Account> {
        #[metrics(+"register_account")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account: Account = self.object.build(authority);
            let account_id = account.id().clone();

            if *account_id.domain() == *iroha_genesis::GENESIS_DOMAIN_ID {
                return Err(InstructionExecutionError::InvariantViolation(
                    "Not allowed to register account in genesis domain".to_owned(),
                ));
            }

            let _domain = state_transaction.world.domain_mut(&account_id.domain)?;
            if state_transaction.world.account(&account_id).is_ok() {
                return Err(RepetitionError {
                    instruction: InstructionType::Register,
                    id: IdBox::AccountId(account_id),
                }
                .into());
            }
            state_transaction
                .world
                .accounts
                .insert(account_id, account.clone());

            state_transaction
                .world
                .emit_events(Some(DomainEvent::Account(AccountEvent::Created(account))));

            Ok(())
        }
    }

    impl Execute for Unregister<Account> {
        #[metrics(+"unregister_account")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let account_id = self.object;

            state_transaction
                .world()
                .triggers()
                .inspect_by_action(
                    |action| action.authority() == &account_id,
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

            state_transaction
                .world
                .account_permissions
                .remove(account_id.clone());

            state_transaction.world.remove_account_roles(&account_id);

            let remove_assets: Vec<AssetId> = state_transaction
                .world
                .assets_in_account_iter(&account_id)
                .map(|ad| ad.id().clone())
                .collect();
            for asset_id in remove_assets {
                state_transaction.world.assets.remove(asset_id);
            }

            if state_transaction
                .world
                .accounts
                .remove(account_id.clone())
                .is_none()
            {
                return Err(FindError::Account(account_id).into());
            }

            state_transaction
                .world
                .emit_events(Some(AccountEvent::Deleted(account_id)));

            Ok(())
        }
    }

    impl Execute for SetKeyValue<Domain> {
        #[metrics(+"set_domain_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain_id = self.object;

            let domain = state_transaction.world.domain_mut(&domain_id)?;
            domain.metadata.insert(self.key.clone(), self.value.clone());

            state_transaction
                .world
                .emit_events(Some(DomainEvent::MetadataInserted(MetadataChanged {
                    target: domain_id,
                    key: self.key,
                    value: self.value,
                })));

            Ok(())
        }
    }

    impl Execute for RemoveKeyValue<Domain> {
        #[metrics(+"remove_domain_key_value")]
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let domain_id = self.object;

            let domain = state_transaction.world.domain_mut(&domain_id)?;
            let value = domain
                .metadata
                .remove(&self.key)
                .ok_or_else(|| FindError::MetadataKey(self.key.clone()))?;

            state_transaction
                .world
                .emit_events(Some(DomainEvent::MetadataRemoved(MetadataChanged {
                    target: domain_id,
                    key: self.key,
                    value,
                })));

            Ok(())
        }
    }

    impl Execute for Transfer<Account, DomainId, Account> {
        fn execute(
            self,
            _authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let Transfer {
                source,
                object,
                destination,
            } = self;

            let _ = state_transaction.world.account(&source)?;
            let _ = state_transaction.world.account(&destination)?;

            let domain = state_transaction.world.domain_mut(&object)?;

            if domain.owned_by != source {
                return Err(Error::InvariantViolation(format!(
                    "Can't transfer domain {domain} since {source} doesn't own it",
                )));
            }

            domain.owned_by = destination.clone();
            state_transaction
                .world
                .emit_events(Some(DomainEvent::OwnerChanged(DomainOwnerChanged {
                    domain: object,
                    new_owner: destination,
                })));

            Ok(())
        }
    }
}

/// Query module provides [`Query`] Domain related implementations.
pub mod query {
    use eyre::Result;
    use iroha_data_model::{
        domain::Domain,
        query::{
            error::QueryExecutionFail as Error,
            predicate::{predicate_atoms::domain::DomainPredicateBox, CompoundPredicate},
        },
    };
    use iroha_primitives::json::Json;

    use super::*;
    use crate::{smartcontracts::ValidQuery, state::StateReadOnly};

    impl ValidQuery for FindDomains {
        #[metrics(+"find_domains")]
        fn execute(
            self,
            filter: CompoundPredicate<DomainPredicateBox>,
            state_ro: &impl StateReadOnly,
        ) -> std::result::Result<impl Iterator<Item = Domain>, Error> {
            Ok(state_ro
                .world()
                .domains_iter()
                .filter(move |&v| filter.applies(v))
                .cloned())
        }
    }

    impl ValidSingularQuery for FindDomainMetadata {
        #[metrics(+"find_domain_key_value_by_id_and_key")]
        fn execute(&self, state_ro: &impl StateReadOnly) -> Result<Json, Error> {
            let id = &self.id;
            let key = &self.key;
            iroha_logger::trace!(%id, %key);
            state_ro
                .world()
                .map_domain(id, |domain| domain.metadata.get(key).cloned())?
                .ok_or_else(|| FindError::MetadataKey(key.clone()).into())
                .map(Into::into)
        }
    }
}
