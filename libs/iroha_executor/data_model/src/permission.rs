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
        pub struct CanUnregisterAnyPeer;
    }
}

pub mod domain {
    use super::*;

    permission! {
        pub struct CanUnregisterDomain {
            pub domain: DomainId,
        }
    }

    permission! {
        pub struct CanSetKeyValueInDomain {
            pub domain: DomainId,
        }
    }

    permission! {
        pub struct CanRemoveKeyValueInDomain {
            pub domain: DomainId,
        }
    }

    permission! {
        pub struct CanRegisterAccountInDomain {
            pub domain: DomainId,
        }
    }

    permission! {
        pub struct CanRegisterAssetDefinitionInDomain {
            pub domain: DomainId,
        }
    }
}

pub mod asset_definition {
    use super::*;

    permission! {
        pub struct CanUnregisterAssetDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanSetKeyValueInAssetDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanRemoveKeyValueInAssetDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }
}

pub mod account {
    use super::*;

    permission! {
        pub struct CanUnregisterAccount {
            pub account: AccountId,
        }
    }
    permission! {
        pub struct CanSetKeyValueInAccount {
            pub account: AccountId,
        }
    }
    permission! {
        pub struct CanRemoveKeyValueInAccount {
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
        pub struct CanUnregisterUserAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanBurnAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanBurnUserAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanMintAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanMintUserAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanTransferAssetWithDefinition {
            pub asset_definition: AssetDefinitionId,
        }
    }

    permission! {
        pub struct CanTransferUserAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanSetKeyValueInUserAsset {
            pub asset: AssetId,
        }
    }

    permission! {
        pub struct CanRemoveKeyValueInUserAsset {
            pub asset: AssetId,
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
        pub struct CanUnregisterAnyRole;
    }
}

pub mod trigger {
    use super::*;

    permission! {
        pub struct CanRegisterUserTrigger {
            pub account: AccountId,
        }
    }

    permission! {
        pub struct CanExecuteUserTrigger {
            pub trigger: TriggerId,
        }
    }

    permission! {
        pub struct CanUnregisterUserTrigger {
            pub account: AccountId,
        }
    }

    permission! {
        pub struct CanMintUserTrigger {
            pub trigger: TriggerId,
        }
    }

    permission! {
        pub struct CanBurnUserTrigger {
            pub trigger: TriggerId,
        }
    }

    permission! {
        pub struct CanSetKeyValueInTrigger {
            pub trigger: TriggerId,
        }
    }

    permission! {
        pub struct CanRemoveKeyValueInTrigger {
            pub trigger: TriggerId,
        }
    }
}

pub mod executor {
    use super::*;

    permission! {
        #[derive(Copy)]
        pub struct CanUpgradeExecutor;
    }
}
