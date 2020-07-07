use crate::prelude::*;
use parity_scale_codec::{Decode, Encode};

pub fn permission_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::new("permissions", "global")
}

#[derive(Clone, Debug, Default, Encode, Decode)]
pub struct Permissions {
    origin: Vec<Permission>,
}

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub enum Permission {
    Anything,
    AddDomain,
    AddListener,
    RegisterAssetDefinition(Option<<Domain as Identifiable>::Id>),
    RegisterAccount(Option<<Domain as Identifiable>::Id>),
    MintAsset(
        Option<<Domain as Identifiable>::Id>,
        Option<<AssetDefinition as Identifiable>::Id>,
    ),
    DemintAsset(
        Option<<Domain as Identifiable>::Id>,
        Option<<AssetDefinition as Identifiable>::Id>,
    ),
    TransferAsset(
        Option<<Domain as Identifiable>::Id>,
        Option<<AssetDefinition as Identifiable>::Id>,
    ),
    AddSignatory(
        Option<<Domain as Identifiable>::Id>,
        Option<<Account as Identifiable>::Id>,
    ),
    RemoveSignatory(
        Option<<Domain as Identifiable>::Id>,
        Option<<Account as Identifiable>::Id>,
    ),
}

impl Permissions {
    pub fn new() -> Self {
        Permissions::default()
    }

    pub fn single(permission: Permission) -> Self {
        Permissions {
            origin: vec![permission],
        }
    }
}

pub mod isi {
    use super::*;
    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};

    /// Iroha special instructions related to `Permission`.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum PermissionInstruction {
        CanAnything(<Account as Identifiable>::Id),
        CanAddListener(<Account as Identifiable>::Id),
        CanAddDomain(<Account as Identifiable>::Id),
        CanRegisterAccount(
            <Account as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanRegisterAssetDefinition(
            <Account as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanTransferAsset(
            <Account as Identifiable>::Id,
            <AssetDefinition as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanAddSignatory(
            <Account as Identifiable>::Id,
            <Account as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanRemoveSignatory(
            <Account as Identifiable>::Id,
            <Account as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanMintAsset(
            <Account as Identifiable>::Id,
            <AssetDefinition as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
        CanDemintAsset(
            <Account as Identifiable>::Id,
            <AssetDefinition as Identifiable>::Id,
            Option<<Domain as Identifiable>::Id>,
        ),
    }

    impl From<&PermissionInstruction> for Permission {
        fn from(instruction: &PermissionInstruction) -> Self {
            match instruction {
                PermissionInstruction::CanAnything(_) => Permission::Anything,
                PermissionInstruction::CanAddDomain(_) => Permission::AddDomain,
                PermissionInstruction::CanAddListener(_) => Permission::AddListener,
                PermissionInstruction::CanRegisterAccount(_, option_domain_id) => {
                    Permission::RegisterAccount(option_domain_id.clone())
                }
                PermissionInstruction::CanRegisterAssetDefinition(_, option_domain_id) => {
                    Permission::RegisterAssetDefinition(option_domain_id.clone())
                }
                PermissionInstruction::CanTransferAsset(
                    _,
                    asset_definition_id,
                    option_domain_id,
                ) => Permission::TransferAsset(
                    option_domain_id.clone(),
                    Some(asset_definition_id.clone()),
                ),
                PermissionInstruction::CanAddSignatory(_, account_id, option_domain_id) => {
                    Permission::AddSignatory(option_domain_id.clone(), Some(account_id.clone()))
                }
                PermissionInstruction::CanRemoveSignatory(_, account_id, option_domain_id) => {
                    Permission::RemoveSignatory(option_domain_id.clone(), Some(account_id.clone()))
                }
                PermissionInstruction::CanMintAsset(_, asset_definition_id, option_domain_id) => {
                    Permission::MintAsset(
                        option_domain_id.clone(),
                        Some(asset_definition_id.clone()),
                    )
                }
                PermissionInstruction::CanDemintAsset(_, asset_definition_id, option_domain_id) => {
                    Permission::DemintAsset(
                        option_domain_id.clone(),
                        Some(asset_definition_id.clone()),
                    )
                }
            }
        }
    }
}
