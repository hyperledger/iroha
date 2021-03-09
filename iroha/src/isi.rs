//! This module contains enumeration of all possible Iroha Special Instructions `Instruction`,
//! generic instruction types and related implementations.
use crate::{expression::Evaluate, prelude::*};
use iroha_data_model::{expression::prelude::*, isi::*, prelude::*};
use iroha_derive::log;
use iroha_error::{Error, Result};

/// Trait implementations should provide actions to apply changes on `WorldStateView`.
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
            _ => Err(Error::msg("Unsupported instruction.")),
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
            _ => Err(Error::msg("Unsupported instruction.")),
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
                _ => Err(Error::msg("Unsupported instruction.")),
            },
            IdBox::WorldId => match self.object.evaluate(world_state_view, &context)? {
                Value::Parameter(parameter) => Mint::<World, Parameter>::new(parameter, WorldId)
                    .execute(authority, world_state_view),
                _ => Err(Error::msg("Unsupported instruction.")),
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
                    _ => Err(Error::msg("Unsupported instruction.")),
                }
            }
            _ => Err(Error::msg("Unsupported instruction.")),
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
                _ => Err(Error::msg("Unsupported instruction.")),
            },
            IdBox::AccountId(account_id) => {
                match self.object.evaluate(world_state_view, &context)? {
                    Value::PublicKey(public_key) => {
                        Burn::<Account, PublicKey>::new(public_key, account_id)
                            .execute(authority, world_state_view)
                    }
                    _ => Err(Error::msg("Unsupported instruction.")),
                }
            }
            _ => Err(Error::msg("Unsupported instruction.")),
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
                        _ => Err(Error::msg("Unsupported instruction.")),
                    },
                    _ => Err(Error::msg("Unsupported instruction.")),
                }
            }
            _ => Err(Error::msg("Unsupported instruction.")),
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
            self.then.execute(authority, &world_state_view)
        } else if let Some(otherwise) = self.otherwise {
            otherwise.execute(authority, world_state_view)
        } else {
            Ok(world_state_view.clone())
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
        Err(Error::msg(format!("Execution failed: {}.", self.message)))
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use super::Execute;
    pub use crate::{account::isi::*, asset::isi::*, domain::isi::*, isi::*, world::isi::*};
}
