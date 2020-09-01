//! This module contains enumeration of all possible Iroha Special Instructions `Instruction`,
//! generic instruction types and related implementations.
use crate::prelude::*;
use iroha_data_model::{isi::*, prelude::*};
use iroha_derive::log;

/// Trait implementations should provide actions to apply changes on `WorldStateView`.
pub trait Execute {
    /// Apply actions to `world_state_view` on behalf of `authority`.
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String>;
}

impl Execute for InstructionBox {
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        use InstructionBox::*;
        match self {
            Add(add_box) => add_box.execute(authority, world_state_view),
            Subtract(substract_box) => substract_box.execute(authority, world_state_view),
            Register(register_box) => register_box.execute(authority, world_state_view),
            Unregister(unregister_box) => unregister_box.execute(authority, world_state_view),
            Mint(mint_box) => mint_box.execute(authority, world_state_view),
            Burn(burn_box) => burn_box.execute(authority, world_state_view),
            Transfer(transfer_box) => transfer_box.execute(authority, world_state_view),
            If(if_box) => if_box.execute(authority, world_state_view),
            Greater(greater_box) => greater_box.execute(authority, world_state_view),
            Pair(pair_box) => pair_box.execute(authority, world_state_view),
            Sequence(sequence_box) => sequence_box.execute(authority, world_state_view),
            Fail(fail_box) => fail_box.execute(authority, world_state_view),
            Not(not_box) => not_box.execute(authority, world_state_view),
        }
    }
}

impl Execute for AddBox {
    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        _world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        Err("Not implemented yet.".to_string())
    }
}

impl Execute for SubtractBox {
    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        _world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        Err("Not implemented yet.".to_string())
    }
}

impl Execute for RegisterBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.destination_id {
            IdBox::DomainName(domain_name) => match self.object {
                IdentifiableBox::Account(account) => {
                    Register::<Domain, Account>::new(*account, domain_name)
                        .execute(authority, world_state_view)
                }
                IdentifiableBox::AssetDefinition(asset_definition) => {
                    Register::<Domain, AssetDefinition>::new(*asset_definition, domain_name)
                        .execute(authority, world_state_view)
                }
                _ => Err("Unsupported instruction.".to_string()),
            },
            IdBox::PeerId(peer_id) => match self.object {
                IdentifiableBox::Domain(domain) => Register::<Peer, Domain>::new(*domain, peer_id)
                    .execute(authority, world_state_view),
                _ => Err("Unsupported instruction.".to_string()),
            },
            _ => Err("Unsupported instruction.".to_string()),
        }
    }
}

impl Execute for UnregisterBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.destination_id {
            IdBox::DomainName(domain_name) => match self.object {
                IdentifiableBox::Account(account) => {
                    Unregister::<Domain, Account>::new(*account, domain_name)
                        .execute(authority, world_state_view)
                }
                IdentifiableBox::AssetDefinition(asset_definition) => {
                    Unregister::<Domain, AssetDefinition>::new(*asset_definition, domain_name)
                        .execute(authority, world_state_view)
                }
                _ => Err("Unsupported instruction.".to_string()),
            },
            IdBox::PeerId(peer_id) => match self.object {
                IdentifiableBox::Domain(domain) => {
                    Unregister::<Peer, Domain>::new(*domain, peer_id)
                        .execute(authority, world_state_view)
                }
                _ => Err("Unsupported instruction.".to_string()),
            },
            _ => Err("Unsupported instruction.".to_string()),
        }
    }
}

impl Execute for MintBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.destination_id {
            IdBox::AssetId(asset_id) => match self.object {
                ValueBox::U32(quantity) => {
                    Mint::<Asset, u32>::new(quantity, asset_id).execute(authority, world_state_view)
                }
                _ => Err("Unsupported instruction.".to_string()),
            },
            _ => Err("Unsupported instruction.".to_string()),
        }
    }
}

impl Execute for BurnBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.destination_id {
            IdBox::AssetId(asset_id) => match self.object {
                ValueBox::U32(quantity) => {
                    Burn::<Asset, u32>::new(quantity, asset_id).execute(authority, world_state_view)
                }
                _ => Err("Unsupported instruction.".to_string()),
            },
            _ => Err("Unsupported instruction.".to_string()),
        }
    }
}

impl Execute for TransferBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.source_id {
            IdBox::AssetId(source_asset_id) => match self.object {
                ValueBox::U32(quantity) => match self.destination_id {
                    IdBox::AssetId(destination_asset_id) => Transfer::<Asset, u32, Asset>::new(
                        source_asset_id,
                        quantity,
                        destination_asset_id,
                    )
                    .execute(authority, world_state_view),
                    _ => Err("Unsupported instruction.".to_string()),
                },
                ValueBox::Query(query_box) => match self.destination_id {
                    IdBox::AssetId(destination_asset_id) => match *query_box {
                        QueryBox::FindAssetQuantityById(query) => {
                            if let QueryResult::FindAssetQuantityById(result) =
                                query.execute(&world_state_view)?
                            {
                                let quantity = result.quantity;
                                return Transfer::<Asset, u32, Asset>::new(
                                    source_asset_id,
                                    quantity,
                                    destination_asset_id,
                                )
                                .execute(authority, world_state_view);
                            } else {
                                Err("Wrong query result.".to_string())
                            }
                        }
                        _ => Err("Unsupported instruction.".to_string()),
                    },
                    _ => Err("Unsupported instruction.".to_string()),
                },
            },
            _ => Err("Unsupported instruction.".to_string()),
        }
    }
}

impl Execute for If {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.condition.execute(authority.clone(), world_state_view) {
            Ok(world_state_view) => self.then.execute(authority, &world_state_view),
            Err(_) => {
                if let Some(otherwise) = self.otherwise {
                    otherwise.execute(authority, world_state_view)
                } else {
                    Ok(world_state_view.clone())
                }
            }
        }
    }
}

impl Execute for GreaterBox {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.left {
            ValueBox::U32(left_value) => match self.right {
                ValueBox::U32(right_value) => {
                    Greater::new(left_value, right_value).execute(authority, world_state_view)
                }
                _ => Err("Unsupported instruction.".to_string()),
            },
            _ => Err("Unsupported instruction.".to_string()),
        }
    }
}

impl Execute for Greater<u32, u32> {
    #[log]
    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        if self.left > self.right {
            Ok(world_state_view.clone())
        } else {
            Err("Value is not greater.".to_string())
        }
    }
}

impl Execute for Pair {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        let world_state_view = self
            .left_instruction
            .execute(authority.clone(), world_state_view)?;
        let world_state_view = self
            .right_instruction
            .execute(authority, &world_state_view)?;
        Ok(world_state_view)
    }
}

impl Execute for Sequence {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        let mut world_state_view = world_state_view.clone();
        for instruction in self.instructions {
            world_state_view = instruction.execute(authority.clone(), &world_state_view)?;
        }
        Ok(world_state_view)
    }
}

impl Execute for Fail {
    #[log]
    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        _world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        Err(format!("Execution failed: {}.", self.message))
    }
}

impl Execute for Not {
    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        world_state_view: &WorldStateView,
    ) -> Result<WorldStateView, String> {
        match self.instruction.execute(authority, world_state_view) {
            Ok(_) => Err("Not.".to_string()),
            Err(_) => Ok(world_state_view.clone()),
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use super::Execute;
    pub use crate::{account::isi::*, asset::isi::*, domain::isi::*, isi::*, peer::isi::*};
}
