//! This module contains enumeration of all possible Iroha Special Instructions `Instruction`,
//! generic instruction types and related implementations.
use crate::{expression::Evaluate, prelude::*};
use iroha_data_model::{expression::prelude::*, isi::*, prelude::*};
use iroha_derive::log;
use iroha_error::{error, Result};

/// Trait implementations should provide actions to apply changes on `WorldStateView`.
#[allow(clippy::missing_errors_doc)]
pub trait Execute {
    /// Apply actions to `world_state_view` on behalf of `authority`.
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView>;
}

impl Execute for Instruction {
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        use Instruction::*;
        match self {
            Register(register_box) => register_box.execute(authority, world_state_view),
            Unregister(unregister_box) => unregister_box.execute(authority, world_state_view),
            Mint(mint_box) => mint_box.execute(authority, world_state_view),
            Burn(burn_box) => burn_box.execute(authority, world_state_view),
            Transfer(transfer_box) => transfer_box.execute(authority, world_state_view),
            If(if_box) => if_box.execute(authority, world_state_view),
            Pair(pair_box) => pair_box.execute(authority, world_state_view),
            Sequence(sequence) => sequence.execute(authority, world_state_view),
            Fail(fail_box) => fail_box.execute(authority, world_state_view),
            SetKeyValue(set_key_value) => set_key_value.execute(authority, world_state_view),
            RemoveKeyValue(remove_key_value) => {
                remove_key_value.execute(authority, world_state_view)
            }
        }
    }
}

impl Execute for RegisterBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        match self.object.evaluate(world_state_view, &context)? {
            IdentifiableBox::Account(account) => {
                Register::<Account>::new(*account).execute(authority, world_state_view)
            }
            IdentifiableBox::AssetDefinition(asset_definition) => {
                Register::<AssetDefinition>::new(*asset_definition)
                    .execute(authority, world_state_view)
            }
            IdentifiableBox::Domain(domain) => {
                Register::<Domain>::new(*domain).execute(authority, world_state_view)
            }
            IdentifiableBox::Peer(peer) => {
                Register::<Peer>::new(*peer).execute(authority, world_state_view)
            }
            _ => Err(error!("Unsupported instruction.")),
        }
    }
}

impl Execute for UnregisterBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        match self.object_id.evaluate(world_state_view, &context)? {
            IdBox::AccountId(account_id) => {
                Unregister::<Account>::new(account_id).execute(authority, world_state_view)
            }
            IdBox::AssetDefinitionId(asset_definition_id) => {
                Unregister::<AssetDefinition>::new(asset_definition_id)
                    .execute(authority, world_state_view)
            }
            IdBox::DomainName(domain_name) => {
                Unregister::<Domain>::new(domain_name).execute(authority, world_state_view)
            }
            _ => Err(error!("Unsupported instruction.")),
        }
    }
}

impl Execute for MintBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        match self.destination_id.evaluate(world_state_view, &context)? {
            IdBox::AssetId(asset_id) => match self.object.evaluate(world_state_view, &context)? {
                Value::U32(quantity) => {
                    Mint::<Asset, u32>::new(quantity, asset_id).execute(authority, world_state_view)
                }
                _ => Err(error!("Unsupported instruction.")),
            },
            IdBox::WorldId => match self.object.evaluate(world_state_view, &context)? {
                Value::Parameter(parameter) => Mint::<World, Parameter>::new(parameter, WorldId)
                    .execute(authority, world_state_view),
                _ => Err(error!("Unsupported instruction.")),
            },
            IdBox::AccountId(account_id) => {
                match self.object.evaluate(world_state_view, &context)? {
                    Value::PublicKey(public_key) => {
                        Mint::<Account, PublicKey>::new(public_key, account_id)
                            .execute(authority, world_state_view)
                    }
                    Value::SignatureCheckCondition(condition) => {
                        Mint::<Account, SignatureCheckCondition>::new(condition, account_id)
                            .execute(authority, world_state_view)
                    }
                    _ => Err(error!("Unsupported instruction.")),
                }
            }
            _ => Err(error!("Unsupported instruction.")),
        }
    }
}

impl Execute for BurnBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        match self.destination_id.evaluate(world_state_view, &context)? {
            IdBox::AssetId(asset_id) => match self.object.evaluate(world_state_view, &context)? {
                Value::U32(quantity) => {
                    Burn::<Asset, u32>::new(quantity, asset_id).execute(authority, world_state_view)
                }
                _ => Err(error!("Unsupported instruction.")),
            },
            IdBox::AccountId(account_id) => {
                match self.object.evaluate(world_state_view, &context)? {
                    Value::PublicKey(public_key) => {
                        Burn::<Account, PublicKey>::new(public_key, account_id)
                            .execute(authority, world_state_view)
                    }
                    _ => Err(error!("Unsupported instruction.")),
                }
            }
            _ => Err(error!("Unsupported instruction.")),
        }
    }
}

impl Execute for TransferBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        match self.source_id.evaluate(world_state_view, &context)? {
            IdBox::AssetId(source_asset_id) => {
                match self.object.evaluate(world_state_view, &context)? {
                    Value::U32(quantity) => match self
                        .destination_id
                        .evaluate(world_state_view, &context)?
                    {
                        IdBox::AssetId(destination_asset_id) => Transfer::<Asset, u32, Asset>::new(
                            source_asset_id,
                            quantity,
                            destination_asset_id,
                        )
                        .execute(authority, world_state_view),
                        _ => Err(error!("Unsupported instruction.")),
                    },
                    _ => Err(error!("Unsupported instruction.")),
                }
            }
            _ => Err(error!("Unsupported instruction.")),
        }
    }
}

impl Execute for SetKeyValueBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        match self.object_id.evaluate(world_state_view, &context)? {
            IdBox::AssetId(asset_id) => {
                let key = self.key.evaluate(world_state_view, &context)?;
                let value = self.value.evaluate(world_state_view, &context)?;
                SetKeyValue::<Asset, String, Value>::new(asset_id, key, value)
                    .execute(authority, world_state_view)
            }
            IdBox::AccountId(account_id) => {
                let key = self.key.evaluate(world_state_view, &context)?;
                let value = self.value.evaluate(world_state_view, &context)?;
                SetKeyValue::<Account, String, Value>::new(account_id, key, value)
                    .execute(authority, world_state_view)
            }
            _ => Err(error!("Unsupported instruction.")),
        }
    }
}

impl Execute for RemoveKeyValueBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        match self.object_id.evaluate(world_state_view, &context)? {
            IdBox::AssetId(asset_id) => {
                let key = self.key.evaluate(world_state_view, &context)?;
                RemoveKeyValue::<Asset, String>::new(asset_id, key)
                    .execute(authority, world_state_view)
            }
            IdBox::AccountId(account_id) => {
                let key = self.key.evaluate(world_state_view, &context)?;
                RemoveKeyValue::<Account, String>::new(account_id, key)
                    .execute(authority, world_state_view)
            }
            _ => Err(error!("Unsupported instruction.")),
        }
    }
}

impl Execute for If {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let context = Context::new();
        if self.condition.evaluate(world_state_view, &context)? {
            self.then.execute(authority, world_state_view)
        } else {
            self.otherwise.map_or_else(
                || Ok(world_state_view.clone()),
                |otherwise| otherwise.execute(authority, world_state_view),
            )
        }
    }
}

impl Execute for Pair {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let world_state_view = self
            .left_instruction
            .execute(authority.clone(), world_state_view)?;
        let world_state_view = self
            .right_instruction
            .execute(authority, &world_state_view)?;
        Ok(world_state_view)
    }
}

impl Execute for SequenceBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        let mut world_state_view = world_state_view.clone();
        for instruction in self.instructions {
            world_state_view = instruction.execute(authority.clone(), &world_state_view)?;
        }
        Ok(world_state_view)
    }
}

impl Execute for FailBox {
    #[log]
    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        _world_state_view: &WorldStateView,
    ) -> Result<WorldStateView> {
        Err(error!("Execution failed: {}.", self.message))
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use super::Execute;
    pub use crate::{account::isi::*, asset::isi::*, domain::isi::*, isi::*, world::isi::*};
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use iroha_data_model::{domain::DomainsMap, peer::PeersIds, TryAsRef};

    fn world_with_test_domains() -> Result<World> {
        let mut domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        let key_pair = KeyPair::generate()?;
        account.signatories.push(key_pair.public_key);
        let _ = domain.accounts.insert(account_id.clone(), account);
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        let _ = domain.asset_definitions.insert(
            asset_definition_id.clone(),
            AssetDefinitionEntry::new(AssetDefinition::new(asset_definition_id), account_id),
        );
        let _ = domains.insert("wonderland".to_string(), domain);
        Ok(World::with(domains, PeersIds::new()))
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let account_id = AccountId::new("alice", "wonderland");
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        let wsv = SetKeyValueBox::new(
            IdBox::from(asset_id.clone()),
            "Bytes".to_string(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id.clone(), &wsv)?;
        let asset_store: &Metadata = wsv
            .read_account(&account_id)
            .ok_or_else(|| error!("Failed to find account."))?
            .assets
            .get(&asset_id)
            .ok_or_else(|| error!("Failed to find asset."))?
            .try_as_ref()?;
        let bytes = asset_store.get("Bytes");
        assert_eq!(
            bytes,
            Some(&Value::Vec(vec![
                Value::U32(1),
                Value::U32(2),
                Value::U32(3)
            ]))
        );
        Ok(())
    }

    #[test]
    fn account_metadata() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let account_id = AccountId::new("alice", "wonderland");
        let wsv = SetKeyValueBox::new(
            IdBox::from(account_id.clone()),
            "Bytes".to_string(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id.clone(), &wsv)?;
        let bytes = wsv
            .read_account(&account_id)
            .ok_or_else(|| error!("Failed to find account."))?
            .metadata
            .get("Bytes");
        assert_eq!(
            bytes,
            Some(&Value::Vec(vec![
                Value::U32(1),
                Value::U32(2),
                Value::U32(3)
            ]))
        );
        Ok(())
    }
}
