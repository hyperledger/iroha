//! This module contains enumeration of all possible Iroha Special Instructions `Instruction`,
//! generic instruction types and related implementations.
pub mod account;
pub mod asset;
pub mod domain;
pub mod expression;
pub mod permissions;
pub mod query;
pub mod tx;
pub mod world;

use std::{
    error::Error as StdError,
    fmt::{self, Display, Formatter},
};

use eyre::{eyre, Result};
use iroha_crypto::HashOf;
use iroha_data_model::{expression::prelude::*, isi::*, prelude::*};
use iroha_logger::prelude::*;
use iroha_macro::FromVariant;
use thiserror::Error;

use super::{Evaluate, Execute};
use crate::{prelude::*, wsv::WorldTrait};

/// Instruction execution error type
#[derive(Debug, FromVariant, Error)]
pub enum Error {
    /// Failed to find some entity
    #[error("Failed to find")]
    Find(#[source] Box<FindError>),
    /// Failed to assert type
    #[error("Failed to assert type")]
    Type(#[source] TypeError),
    /// Failed to assert mintability
    #[error("Failed to assert mintability")]
    Mintability(#[source] MintabilityError),
    /// Failed due to math exception
    #[error("Math error occurred")]
    Math(#[source] MathError),
    /// Some other error happened
    #[error("Some other error happened")]
    Other(#[skip_try_from] eyre::Error),
}

/// Type assertion error
#[derive(Debug, Clone, Error)]
pub enum FindError {
    /// Failed to find asset
    #[error("Failed to find asset: `{0}`")]
    Asset(AssetId),
    /// Failed to find asset definition
    #[error("Failed to find asset definition: `{0}`")]
    AssetDefinition(AssetDefinitionId),
    /// Failed to find account
    #[error("Failed to find account: `{0}`")]
    Account(AccountId),
    /// Failed to find domain
    #[error("Failed to find domain: `{0}`")]
    Domain(Name),
    /// Failed to find metadata key
    #[error("Failed to find metadata key")]
    MetadataKey(Name),
    /// Failed to find Role by id.
    #[cfg(feature = "roles")]
    #[error("Failed to find role by id: `{0}`")]
    Role(RoleId),
    /// Block with supplied parent hash not found. More description in a string.
    #[error("Block not found")]
    Block(#[source] ParentHashNotFound),
}

/// Mintability logic error
#[derive(Debug, Clone, FromVariant, Error, Copy)]
pub enum MintabilityError {
    /// Tried to mint an Un-mintable asset.
    #[error("Minting of this asset is forbidden")]
    MintUnmintableError,
}

/// Type assertion error
#[derive(Debug, Clone, FromVariant, Error, Copy)]
pub enum TypeError {
    /// Asset type assertion error
    #[error("Failed to assert type of asset")]
    Asset(#[source] AssetTypeError),
}

/// Asset type assertion error
#[derive(Debug, Clone, Copy)]
pub struct AssetTypeError {
    /// Expected type
    pub expected: AssetValueType,
    /// Type which was discovered
    pub got: AssetValueType,
}

impl Display for AssetTypeError {
    #[allow(clippy::use_debug)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Asset type error: expected asset of type {:?}, but got {:?}",
            self.expected, self.got
        )
    }
}

impl StdError for AssetTypeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

/// Math error type inside instruction
#[derive(Debug, Clone, FromVariant, Error, Copy)]
pub enum MathError {
    /// Overflow error inside instruction
    #[error("Overflow occurred.")]
    OverflowError,
    /// Not enough quantity
    #[error("Not enough quantity to burn.")]
    NotEnoughQuantity,
}

/// Block with parent hash not found struct
#[derive(Debug, Clone, Copy)]
pub struct ParentHashNotFound(pub HashOf<VersionedCommittedBlock>);

impl Display for ParentHashNotFound {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Block with parent hash {} not found", self.0)
    }
}

impl StdError for ParentHashNotFound {}

impl<W: WorldTrait> Execute<W> for Instruction {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        use Instruction::*;
        match self {
            Register(register_box) => register_box.execute(authority, wsv),
            Unregister(unregister_box) => unregister_box.execute(authority, wsv),
            Mint(mint_box) => mint_box.execute(authority, wsv),
            Burn(burn_box) => burn_box.execute(authority, wsv),
            Transfer(transfer_box) => transfer_box.execute(authority, wsv),
            If(if_box) => if_box.execute(authority, wsv),
            Pair(pair_box) => pair_box.execute(authority, wsv),
            Sequence(sequence) => sequence.execute(authority, wsv),
            Fail(fail_box) => fail_box.execute(authority, wsv),
            SetKeyValue(set_key_value) => set_key_value.execute(authority, wsv),
            RemoveKeyValue(remove_key_value) => remove_key_value.execute(authority, wsv),
            Grant(grant_box) => grant_box.execute(authority, wsv),
        }
    }
}

impl<W: WorldTrait> Execute<W> for RegisterBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        match self.object.evaluate(wsv, &context)? {
            IdentifiableBox::NewAccount(account) => {
                Register::<NewAccount>::new(*account).execute(authority, wsv)
            }
            IdentifiableBox::AssetDefinition(asset_definition) => {
                Register::<AssetDefinition>::new(*asset_definition).execute(authority, wsv)
            }
            IdentifiableBox::Domain(domain) => {
                Register::<Domain>::new(*domain).execute(authority, wsv)
            }
            IdentifiableBox::Peer(peer) => Register::<Peer>::new(*peer).execute(authority, wsv),
            _ => Err(eyre!("Unsupported register instruction.").into()),
        }
    }
}

impl<W: WorldTrait> Execute<W> for UnregisterBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        match self.object_id.evaluate(wsv, &context)? {
            IdBox::AccountId(account_id) => {
                Unregister::<Account>::new(account_id).execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(asset_definition_id) => {
                Unregister::<AssetDefinition>::new(asset_definition_id).execute(authority, wsv)
            }
            IdBox::DomainName(domain_name) => {
                Unregister::<Domain>::new(domain_name).execute(authority, wsv)
            }
            IdBox::PeerId(peer_id) => Unregister::<Peer>::new(peer_id).execute(authority, wsv),
            _ => Err(eyre!("Unsupported unregister instruction.").into()),
        }
    }
}

impl<W: WorldTrait> Execute<W> for MintBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        match (
            self.destination_id.evaluate(wsv, &context)?,
            self.object.evaluate(wsv, &context)?,
        ) {
            (IdBox::AssetId(asset_id), Value::U32(quantity)) => {
                Mint::<Asset, u32>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::U128(quantity)) => {
                Mint::<Asset, u128>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::Fixed(quantity)) => {
                Mint::<Asset, Fixed>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::PublicKey(public_key)) => {
                Mint::<Account, PublicKey>::new(public_key, account_id).execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::SignatureCheckCondition(condition)) => {
                Mint::<Account, SignatureCheckCondition>::new(condition, account_id)
                    .execute(authority, wsv)
            }
            _ => Err(eyre!("Unsupported mint instruction.").into()),
        }
    }
}

impl<W: WorldTrait> Execute<W> for BurnBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        match (
            self.destination_id.evaluate(wsv, &context)?,
            self.object.evaluate(wsv, &context)?,
        ) {
            (IdBox::AssetId(asset_id), Value::U32(quantity)) => {
                Burn::<Asset, u32>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::Fixed(quantity)) => {
                Burn::<Asset, Fixed>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::PublicKey(public_key)) => {
                Burn::<Account, PublicKey>::new(public_key, account_id).execute(authority, wsv)
            }
            _ => Err(eyre!("Unsupported burn instruction.").into()),
        }
    }
}

impl<W: WorldTrait> Execute<W> for TransferBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        let source_asset_id = match self.source_id.evaluate(wsv, &context)? {
            IdBox::AssetId(source_asset_id) => source_asset_id,
            _ => return Err(eyre!("Unsupported transfer instruction.").into()),
        };

        let quantity = match self.object.evaluate(wsv, &context)? {
            Value::U32(quantity) => quantity,
            _ => return Err(eyre!("Unsupported transfer instruction.").into()),
        };

        match self.destination_id.evaluate(wsv, &context)? {
            IdBox::AssetId(destination_asset_id) => {
                Transfer::<Asset, u32, Asset>::new(source_asset_id, quantity, destination_asset_id)
                    .execute(authority, wsv)
            }
            _ => Err(eyre!("Unsupported transfer instruction.").into()),
        }
    }
}

impl<W: WorldTrait> Execute<W> for SetKeyValueBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        let key = self.key.evaluate(wsv, &context)?;
        let value = self.value.evaluate(wsv, &context)?;
        match self.object_id.evaluate(wsv, &context)? {
            IdBox::AssetId(asset_id) => {
                SetKeyValue::<Asset, String, Value>::new(asset_id, key, value)
                    .execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(definition_id) => {
                SetKeyValue::<AssetDefinition, String, Value>::new(definition_id, key, value)
                    .execute(authority, wsv)
            }
            IdBox::AccountId(account_id) => {
                SetKeyValue::<Account, String, Value>::new(account_id, key, value)
                    .execute(authority, wsv)
            }
            IdBox::DomainName(name) => {
                SetKeyValue::<Domain, String, Value>::new(name, key, value).execute(authority, wsv)
            }
            _ => Err(eyre!("Unsupported set key-value instruction.").into()),
        }
    }
}

impl<W: WorldTrait> Execute<W> for RemoveKeyValueBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        let key = self.key.evaluate(wsv, &context)?;
        match self.object_id.evaluate(wsv, &context)? {
            IdBox::AssetId(asset_id) => {
                RemoveKeyValue::<Asset, String>::new(asset_id, key).execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(definition_id) => {
                RemoveKeyValue::<AssetDefinition, String>::new(definition_id, key)
                    .execute(authority, wsv)
            }
            IdBox::AccountId(account_id) => {
                RemoveKeyValue::<Account, String>::new(account_id, key).execute(authority, wsv)
            }
            _ => Err(eyre!("Unsupported remove key-value instruction.").into()),
        }
    }
}

impl<W: WorldTrait> Execute<W> for If {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        if self.condition.evaluate(wsv, &context)? {
            self.then.execute(authority, wsv)
        } else {
            self.otherwise
                .map_or_else(|| Ok(()), |otherwise| otherwise.execute(authority, wsv))
        }
    }
}

impl<W: WorldTrait> Execute<W> for Pair {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        self.left_instruction.execute(authority.clone(), wsv)?;
        self.right_instruction.execute(authority, wsv)?;
        Ok(())
    }
}

impl<W: WorldTrait> Execute<W> for SequenceBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        for instruction in self.instructions {
            instruction.execute(authority.clone(), wsv)?;
        }
        Ok(())
    }
}

impl<W: WorldTrait> Execute<W> for FailBox {
    type Error = Error;

    #[log(skip(_authority, _wsv))]
    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        Err(eyre!("Execution failed: {}.", self.message).into())
    }
}

impl<W: WorldTrait> Execute<W> for GrantBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Error> {
        let context = Context::new();
        match (
            self.destination_id.evaluate(wsv, &context)?,
            self.object.evaluate(wsv, &context)?,
        ) {
            (IdBox::AccountId(account_id), Value::PermissionToken(permission_token)) => {
                Grant::<Account, PermissionToken>::new(permission_token, account_id)
                    .execute(authority, wsv)
            }
            #[cfg(feature = "roles")]
            (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(role_id))) => {
                Grant::<Account, RoleId>::new(role_id, account_id).execute(authority, wsv)
            }
            _ => Err(eyre!("Unsupported grant instruction.").into()),
        }
    }
}

pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    pub use super::{account::isi::*, asset::isi::*, domain::isi::*, world::isi::*, *};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use iroha_crypto::KeyPair;
    use iroha_data_model::{domain::DomainsMap, peer::PeersIds};

    use super::*;
    use crate::wsv::World;

    fn world_with_test_domains() -> Result<World> {
        let domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        let key_pair = KeyPair::generate()?;
        account.signatories.push(key_pair.public_key);
        domain.accounts.insert(account_id.clone(), account);
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        domain.asset_definitions.insert(
            asset_definition_id.clone(),
            AssetDefinitionEntry::new(AssetDefinition::new_store(asset_definition_id), account_id),
        );
        domains.insert("wonderland".to_string(), domain);
        Ok(World::with(domains, PeersIds::new()))
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::<World>::new(world_with_test_domains()?);
        let account_id = AccountId::new("alice", "wonderland");
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        SetKeyValueBox::new(
            IdBox::from(asset_id.clone()),
            "Bytes".to_owned(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let asset = wsv.asset(&asset_id)?;
        let metadata: &Metadata = asset.try_as_ref()?;
        let bytes = metadata.get("Bytes").cloned();
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
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
        SetKeyValueBox::new(
            IdBox::from(account_id.clone()),
            "Bytes".to_owned(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id.clone(), &wsv)?;
        let bytes = wsv.map_account(&account_id, |account| {
            account.metadata.get("Bytes").cloned()
        })?;
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
                Value::U32(1),
                Value::U32(2),
                Value::U32(3)
            ]))
        );
        Ok(())
    }

    #[test]
    fn asset_definition_metadata() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let definition_id = AssetDefinitionId::new("rose", "wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        SetKeyValueBox::new(
            IdBox::from(definition_id.clone()),
            "Bytes".to_owned(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let bytes = wsv
            .asset_definition_entry(&definition_id)?
            .definition
            .metadata
            .get("Bytes")
            .cloned();
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
                Value::U32(1),
                Value::U32(2),
                Value::U32(3)
            ]))
        );
        Ok(())
    }

    #[test]
    fn domain_metadata() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let domain_name = "wonderland".to_owned();
        let account_id = AccountId::new("alice", "wonderland");
        SetKeyValueBox::new(
            IdBox::from(domain_name.clone()),
            "Bytes".to_owned(),
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let bytes = wsv.domain(&domain_name)?.metadata.get("Bytes").cloned();
        assert_eq!(
            bytes,
            Some(Value::Vec(vec![
                Value::U32(1),
                Value::U32(2),
                Value::U32(3)
            ]))
        );
        Ok(())
    }
}
