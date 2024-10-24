//! Definition of Iroha default permission tokens
#![allow(missing_docs, clippy::missing_errors_doc)]

use alloc::{format, string::String, vec::Vec};

use iroha_data_model::prelude::*;
pub use iroha_executor_data_model_derive::Permission;
use iroha_schema::{Ident, IntoSchema};
use serde::{de::DeserializeOwned, Serialize};

/// Used to check if the permission token is owned by the account.
pub trait Permission: Serialize + DeserializeOwned + IntoSchema {
    /// Permission id, according to [`IntoSchema`].
    fn name() -> Ident {
        Self::type_name()
    }
}

macro_rules! permission {
    ($item:item) => {
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Permission,
            serde::Serialize,
            serde::Deserialize,
            iroha_schema::IntoSchema,
        )]
        $item
    };
}

pub mod peer {
    use super::*;

    permission! {
        #[derive(Copy)]
        pub struct CanManagePeers;
    }
}

pub mod domain {
    use super::*;

    permission! {
        #[derive(Copy)]
        pub struct CanRegisterDomain;
    }

    permission! {
        pub struct CanUnregisterDomain {
            pub domain: DomainId,
        }
    }

    permission! {
        pub struct CanModifyDomainMetadata {
            pub domain: DomainId,
        }
    }
}

pub mod asset_definition {
    use super::*;

    permission! {
        pub struct CanRegisterAssetDefinition {
            pub domain: DomainId,
        }
    }

    permission! {
        pub struct CanUnregisterAssetDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanModifyAssetDefinitionMetadata {
            pub asset_definition: AssetDefinitionId,
        }
    }
}

pub mod account {
    use super::*;

    permission! {
        pub struct CanRegisterAccount {
            pub domain: DomainId,
        }
    }

    permission! {
        pub struct CanUnregisterAccount {
            pub account: AccountId,
        }
    }
    permission! {
        pub struct CanModifyAccountMetadata {
            pub account: AccountId,
        }
    }
}

pub mod asset {
    use super::*;

    permission! {
        pub struct CanRegisterAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanUnregisterAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanMintAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanBurnAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanTransferAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanRegisterAsset {
            pub owner: AccountId,
        }
    }

    permission! {
        pub struct CanUnregisterAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanMintAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanBurnAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanTransferAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanModifyAssetMetadata {
            pub asset: AssetId,
        }
    }
}

pub mod trigger {
    use super::*;

    permission! {
        #[derive(Copy)]
        pub struct CanRegisterAnyTrigger;
    }

    permission! {
        #[derive(Copy)]
        pub struct CanUnregisterAnyTrigger;
    }

    permission! {
        pub struct CanRegisterTrigger {
            pub authority: AccountId,
        }
    }

    permission! {
        pub struct CanUnregisterTrigger {
            pub trigger: TriggerId,
        }
    }

    permission! {
        pub struct CanModifyTrigger {
            pub trigger: TriggerId,
        }
    }

    permission! {
        pub struct CanExecuteTrigger {
            pub trigger: TriggerId,
        }
    }

    permission! {
        pub struct CanModifyTriggerMetadata {
            pub trigger: TriggerId,
        }
    }
}

pub mod parameter {
    use super::*;

    permission! {
        #[derive(Copy)]
        pub struct CanSetParameters;
    }
}

pub mod role {
    use super::*;

    permission! {
        #[derive(Copy)]
        pub struct CanManageRoles;
    }
}

pub mod executor {
    use super::*;

    permission! {
        #[derive(Copy)]
        pub struct CanUpgradeExecutor;
    }
}
