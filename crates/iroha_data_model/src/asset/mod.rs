//! Asset-related types and instructions.
use iroha_primitives::numeric::Quantity;
use std::collections::btree_map;
pub mod alias;
pub mod dataspace_definition;
pub mod definition;
pub mod id;
pub mod instructions;
pub mod policy;
pub mod retail_daily_limit;
pub mod transfer_control;
pub mod value;
pub use alias::{AssetDefinitionAlias, ResolvedAssetDefinitionAliasV1};
pub use dataspace_definition::{AssetDefinitionDirectHomeV1, AssetDefinitionHome};
pub use definition::{AssetBalancePolicy, AssetDefinition, Mintable, NewAssetDefinition};
pub use id::{AssetBalanceScope, AssetDefinitionId, AssetId};
pub use policy::{
    ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, AssetIssuerUsagePolicyV1, AssetSubjectBindingV1,
    DOMAIN_ASSET_USAGE_POLICY_METADATA_KEY, DomainAssetUsagePolicyV1,
};
pub use retail_daily_limit::{
    RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1, RetailDailyActivationV1, RetailDailyLimitPolicyV1,
    RetailDailyUsageKeyV1, RetailIdentityAttestationBodyV1, RetailIdentityAttestationV1,
    RetailIdentityCommitmentV1, RetailInstitutionalExceptionV1, RetailMonetaryPurposeV1,
    RetailMovementPurposeV1,
};
pub use transfer_control::{
    ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1, ASSET_TRANSFER_CONTROL_METADATA_KEY,
    AssetTransferAvailability, AssetTransferControlRecord, AssetTransferControlStoreV1,
    AssetTransferControlWindow, AssetTransferLimit, AssetTransferUsageBucket,
    validate_asset_transfer_availability_reason,
};
pub use value::{Asset, AssetEntry, AssetValue};
/// [`AssetTotalQuantityMap`] stores canonical non-negative totals by asset definition.
pub type AssetTotalQuantityMap = btree_map::BTreeMap<AssetDefinitionId, Quantity>;
/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{
        alias::{AssetDefinitionAlias, ResolvedAssetDefinitionAliasV1},
        dataspace_definition::{AssetDefinitionDirectHomeV1, AssetDefinitionHome},
        definition::{AssetBalancePolicy, AssetDefinition, Mintable, NewAssetDefinition},
        id::{AssetBalanceScope, AssetDefinitionId, AssetId},
        policy::{
            ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, AssetIssuerUsagePolicyV1,
            AssetSubjectBindingV1, DOMAIN_ASSET_USAGE_POLICY_METADATA_KEY,
            DomainAssetUsagePolicyV1,
        },
        transfer_control::{
            ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1, ASSET_TRANSFER_CONTROL_METADATA_KEY,
            AssetTransferAvailability, AssetTransferControlRecord, AssetTransferControlStoreV1,
            AssetTransferControlWindow, AssetTransferLimit, AssetTransferUsageBucket,
            validate_asset_transfer_availability_reason,
        },
        value::Asset,
    };
}
