//! This module contains permissions.

use crate::prelude::*;
use iroha_data_model::prelude::*;

const PERMISSION_NOT_FOUND: &str = "Permission not found.";

/// Special `AssetDefinitionId` for assets of type permission.
pub fn permission_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::new("permissions", "global")
}

pub trait Permission {}

impl Permission for Anything {}
impl Permission for AddDomain {}
impl Permission for RemoveDomain {}
impl Permission for AddTrigger {}
impl Permission for RemoveTrigger {}
impl Permission for RegisterAssetDefinition {}
impl Permission for UnregisterAssetDefinition {}
impl Permission for RegisterAccount {}
impl Permission for UnregisterAccount {}
impl Permission for MintAsset {}
impl Permission for DemintAsset {}
impl Permission for TransferAsset {}
impl Permission for AddSignatory {}
impl Permission for RemoveSignatory {}

pub fn check(
    authority: <Account as Identifiable>::Id,
    permission: Box<dyn Permission>,
    world_state_view: &WorldStateView,
) -> Result<(), String> {
    Ok(())
}
