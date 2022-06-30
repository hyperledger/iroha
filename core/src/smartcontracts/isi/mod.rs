//! This module contains enumeration of all possible Iroha Special
//! Instructions `Instruction`, generic instruction types and related
//! implementations.
pub mod account;
pub mod asset;
pub mod block;
pub mod domain;
pub mod expression;
pub mod permissions;
pub mod query;
pub mod triggers;
pub mod tx;
pub mod world;

pub use error::*;
use eyre::Result;
use iroha_data_model::{expression::prelude::*, isi::*, prelude::*};
use iroha_logger::prelude::*;

use super::{Evaluate, Execute};
use crate::{prelude::*, wsv::WorldStateView};

pub mod error {
    //! Errors used in Iroha special instructions and
    //! queries. Instruction execution should fail with a specific
    //! error variant, as opposed to a generic (printable-only)
    //! [`eyre::Report`]. If it is impossible to predict what kind of
    //! error shall be raised, there are types that wrap
    //! [`eyre::Report`].

    use derive_more::Display;
    use iroha_crypto::HashOf;
    use iroha_data_model::{fixed::FixedPointOperationError, metadata, prelude::*, trigger};
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use thiserror::Error;

    use super::{query, VersionedCommittedBlock};

    /// Instruction execution error type
    #[derive(Debug, Error)]
    pub enum Error {
        /// Failed to find some entity
        #[error("Failed to find. {0}")]
        Find(#[from] Box<FindError>),
        /// Failed to assert type
        #[error("Type assertion failed. {0}")]
        Type(#[from] TypeError),
        /// Failed to assert mintability
        #[error("Mintability violation. {0}")]
        Mintability(#[from] MintabilityError),
        /// Failed due to math exception
        #[error("Math error. {0}")]
        Math(#[from] MathError),
        /// Query Error
        #[error("Query failed. {0}")]
        Query(#[from] query::Error),
        /// Metadata Error.
        #[error("Metadata error: {0}")]
        Metadata(#[from] metadata::Error),
        /// Unsupported instruction.
        #[error("Unsupported {0} instruction")]
        Unsupported(InstructionType),
        /// [`FailBox`] error
        #[error("Execution failed {0}")]
        FailBox(String),
        /// Conversion Error
        #[error("Conversion Error: {0}")]
        Conversion(String),
        /// Repeated instruction
        #[error("Repetition")]
        Repetition(InstructionType, IdBox),
        /// Failed to validate.
        #[error("Failed to validate: {0}")]
        Validate(#[from] ValidationError),
    }

    impl From<FindError> for Error {
        fn from(err: FindError) -> Self {
            Self::Find(Box::new(err))
        }
    }

    impl From<trigger::set::ModRepeatsError> for Error {
        fn from(err: trigger::set::ModRepeatsError) -> Self {
            match err {
                trigger::set::ModRepeatsError::NotFound(not_found_id) => {
                    FindError::Trigger(not_found_id).into()
                }
                trigger::set::ModRepeatsError::RepeatsOverflow(_) => MathError::Overflow.into(),
            }
        }
    }

    /// Enumeration of instructions which can have unsupported variants.
    #[derive(Debug, Display, Clone, Copy)]
    pub enum InstructionType {
        /// Mint
        Mint,
        /// Register.
        Register,
        /// Set key-value pair.
        SetKeyValue,
        /// Remove key-value pair.
        RemoveKeyValue,
        /// Grant
        Grant,
        /// Transfer
        Transfer,
        /// Burn
        Burn,
        /// Un-register.
        Unregister,
        /// Revoke
        Revoke,
    }

    /// Type assertion error
    #[derive(Debug, Error, Decode, Encode, IntoSchema)]
    pub enum FindError {
        /// Failed to find asset
        #[error("Failed to find asset: `{0}`")]
        Asset(AssetId),
        /// Failed to find asset definition
        #[error("Failed to find asset definition: `{0}`")]
        AssetDefinition(AssetDefinitionId),
        /// Failed to find account
        #[error("Failed to find account: `{0}`")]
        Account(<Account as Identifiable>::Id),
        /// Failed to find domain
        #[error("Failed to find domain: `{0}`")]
        Domain(DomainId),
        /// Failed to find metadata key
        #[error("Failed to find metadata key")]
        MetadataKey(Name),
        /// Block with supplied parent hash not found. More description in a string.
        #[error("Block with hash {0} not found.")]
        Block(HashOf<VersionedCommittedBlock>),
        /// Transaction with given hash not found.
        #[error("Transaction not found")]
        Transaction(HashOf<VersionedTransaction>),
        /// Value not found in context.
        #[error("Value named {0} not found in context. ")]
        Context(String),
        /// Peer not found.
        #[error("Peer {0} not found")]
        Peer(PeerId),
        /// Trigger not found.
        #[error("Trigger not found.")]
        Trigger(TriggerId),
        /// Failed to find Role by id.
        #[error("Failed to find role by id: `{0}`")]
        Role(RoleId),
    }

    /// Generic structure used to represent a mismatch
    #[derive(Debug, Clone, PartialEq, Eq, Error, Decode, Encode, IntoSchema)]
    #[error("Expected {expected:?}, actual {actual:?}")]
    pub struct Mismatch<T> {
        /// The value that is needed for normal execution
        pub expected: T,
        /// The value that caused the error
        pub actual: T,
    }

    /// Type error
    #[derive(Debug, Clone, Error, PartialEq, Eq)]
    #[allow(variant_size_differences)] // False-positive
    pub enum TypeError {
        /// Asset type assertion error
        #[error("Asset Ids correspond to assets with different underlying types. {0}")]
        UnderlyingType(#[from] Mismatch<AssetValueType>),
        /// Asset Id mismatch
        #[error("Asset Ids don't match. {0}")]
        DefinitionId(#[from] Box<Mismatch<<AssetDefinition as Identifiable>::Id>>),
    }

    /// Math error, which occurs during instruction execution
    #[derive(Debug, Clone, Error, Copy, PartialEq, Eq)]
    pub enum MathError {
        /// Overflow error inside instruction
        #[error("Overflow occurred.")]
        Overflow,
        /// Not enough quantity
        #[error("Not enough quantity to transfer/burn.")]
        NotEnoughQuantity,
        /// Divide by zero
        #[error("Divide by zero")]
        DivideByZero,
        /// Negative Value encountered
        #[error("Negative value encountered")]
        NegativeValue,
        /// Domain violation
        #[error("Domain violation")]
        DomainViolation,
        /// Unknown error. No actual function should ever return this if possible.
        #[error("Unknown error")]
        Unknown,
    }

    impl From<FixedPointOperationError> for Error {
        fn from(err: FixedPointOperationError) -> Self {
            match err {
                FixedPointOperationError::NegativeValue(_) => Self::Math(MathError::NegativeValue),
                FixedPointOperationError::Conversion(e) => {
                    Self::Conversion(format!("Mathematical conversion failed. {}", e))
                }
                FixedPointOperationError::Overflow => MathError::Overflow.into(),
                FixedPointOperationError::DivideByZero => MathError::DivideByZero.into(),
                FixedPointOperationError::DomainViolation => MathError::DomainViolation.into(),
                FixedPointOperationError::Arithmetic => MathError::Unknown.into(),
            }
        }
    }
}

impl Execute for Instruction {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
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
            Revoke(revoke_box) => revoke_box.execute(authority, wsv),
            ExecuteTrigger(execute_trigger) => execute_trigger.execute(authority, wsv),
        }
    }
}

impl Execute for RegisterBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new();
        let object_id = self.object.evaluate(wsv, &context)?;
        iroha_logger::trace!(?object_id);
        match object_id {
            RegistrableBox::Peer(peer) => Register::<Peer>::new(*peer).execute(authority, wsv),
            RegistrableBox::Domain(domain) => {
                Register::<Domain>::new(*domain).execute(authority, wsv)
            }
            RegistrableBox::Account(account) => {
                Register::<Account>::new(*account).execute(authority, wsv)
            }
            RegistrableBox::AssetDefinition(asset_definition) => {
                Register::<AssetDefinition>::new(*asset_definition).execute(authority, wsv)
            }
            RegistrableBox::Asset(asset) => Register::<Asset>::new(*asset).execute(authority, wsv),
            RegistrableBox::Trigger(trigger) => {
                Register::<Trigger<FilterBox>>::new(*trigger).execute(authority, wsv)
            }
            RegistrableBox::Role(role) => Register::<Role>::new(*role).execute(authority, wsv),
        }
    }
}

impl Execute for UnregisterBox {
    type Error = Error;

    fn execute(self, authority: AccountId, wsv: &WorldStateView) -> Result<(), Self::Error> {
        let context = Context::new();
        let object_id = self.object_id.evaluate(wsv, &context)?;
        iroha_logger::trace!(?object_id, %authority);
        match object_id {
            IdBox::AccountId(account_id) => {
                Unregister::<Account>::new(account_id).execute(authority, wsv)
            }
            IdBox::AssetId(asset_id) => Unregister::<Asset>::new(asset_id).execute(authority, wsv),
            IdBox::AssetDefinitionId(asset_definition_id) => {
                Unregister::<AssetDefinition>::new(asset_definition_id).execute(authority, wsv)
            }
            IdBox::DomainId(domain_id) => {
                Unregister::<Domain>::new(domain_id).execute(authority, wsv)
            }
            IdBox::PeerId(peer_id) => Unregister::<Peer>::new(peer_id).execute(authority, wsv),
            IdBox::RoleId(role_id) => Unregister::<Role>::new(role_id).execute(authority, wsv),
            IdBox::TriggerId(trigger_id) => {
                Unregister::<Trigger<FilterBox>>::new(trigger_id).execute(authority, wsv)
            }
        }
    }
}

impl Execute for MintBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let destination_id = self.destination_id.evaluate(wsv, &context)?;
        let object = self.object.evaluate(wsv, &context)?;
        iroha_logger::trace!(%destination_id, ?object, %authority);
        match (destination_id, object) {
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
            (IdBox::TriggerId(trigger_id), Value::U32(quantity)) => {
                Mint::<Trigger<FilterBox>, u32>::new(quantity, trigger_id).execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::Mint)),
        }
    }
}

impl Execute for BurnBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let destination_id = self.destination_id.evaluate(wsv, &context)?;
        let object = self.object.evaluate(wsv, &context)?;
        iroha_logger::trace!(?destination_id, ?object, %authority);
        match (
            self.destination_id.evaluate(wsv, &context)?,
            self.object.evaluate(wsv, &context)?,
        ) {
            (IdBox::AssetId(asset_id), Value::U32(quantity)) => {
                Burn::<Asset, u32>::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::U128(quantity)) => {
                Burn::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AssetId(asset_id), Value::Fixed(quantity)) => {
                Burn::new(quantity, asset_id).execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::PublicKey(public_key)) => {
                Burn::new(public_key, account_id).execute(authority, wsv)
            }
            // Not implemented yet.
            // (IdBox::AccountId(account_id), Value::SignatureCheckCondition(condition)) => {
            //     Burn::<Account, SignatureCheckCondition>::new(condition, account_id).execute(authority, wsv)
            // }
            _ => Err(Error::Unsupported(InstructionType::Burn)),
        }
    }
}

impl Execute for TransferBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let (source_asset_id, destination_asset_id) = match (
            self.source_id.evaluate(wsv, &context)?,
            self.destination_id.evaluate(wsv, &context)?,
        ) {
            (IdBox::AssetId(src), IdBox::AssetId(dst)) => (src, dst),
            _ => return Err(Error::Unsupported(InstructionType::Transfer)),
        };

        let value = self.object.evaluate(wsv, &context)?;
        iroha_logger::trace!(?source_asset_id, ?destination_asset_id, ?value, %authority);

        match value {
            Value::U32(quantity) => Transfer::new(source_asset_id, quantity, destination_asset_id)
                .execute(authority, wsv),
            Value::U128(quantity) => Transfer::new(source_asset_id, quantity, destination_asset_id)
                .execute(authority, wsv),
            Value::Fixed(quantity) => {
                Transfer::new(source_asset_id, quantity, destination_asset_id)
                    .execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::Transfer)),
        }
    }
}

impl Execute for SetKeyValueBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let key = self.key.evaluate(wsv, &context)?;
        let value = self.value.evaluate(wsv, &context)?;
        iroha_logger::trace!(?key, ?value, %authority);
        match self.object_id.evaluate(wsv, &context)? {
            IdBox::AssetId(asset_id) => {
                SetKeyValue::<Asset, Name, Value>::new(asset_id, key, value).execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(definition_id) => {
                SetKeyValue::<AssetDefinition, Name, Value>::new(definition_id, key, value)
                    .execute(authority, wsv)
            }
            IdBox::AccountId(account_id) => {
                SetKeyValue::<Account, Name, Value>::new(account_id, key, value)
                    .execute(authority, wsv)
            }
            IdBox::DomainId(id) => {
                SetKeyValue::<Domain, Name, Value>::new(id, key, value).execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::SetKeyValue)),
        }
    }
}

impl Execute for RemoveKeyValueBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let key = self.key.evaluate(wsv, &context)?;
        iroha_logger::trace!(?key, %authority);
        match self.object_id.evaluate(wsv, &context)? {
            IdBox::AssetId(asset_id) => {
                RemoveKeyValue::<Asset, Name>::new(asset_id, key).execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(definition_id) => {
                RemoveKeyValue::<AssetDefinition, Name>::new(definition_id, key)
                    .execute(authority, wsv)
            }
            IdBox::AccountId(account_id) => {
                RemoveKeyValue::<Account, Name>::new(account_id, key).execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::RemoveKeyValue)),
        }
    }
}

impl Execute for If {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        iroha_logger::trace!(?self);
        if self.condition.evaluate(wsv, &context)? {
            self.then.execute(authority, wsv)?;
        } else if let Some(otherwise) = self.otherwise {
            otherwise.execute(authority, wsv)?;
        }
        Ok(())
    }
}

impl Execute for Pair {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        iroha_logger::trace!(?self);

        self.left_instruction.execute(authority.clone(), wsv)?;
        self.right_instruction.execute(authority, wsv)?;
        Ok(())
    }
}

impl Execute for SequenceBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        iroha_logger::trace!(?self);

        for instruction in self.instructions {
            instruction.execute(authority.clone(), wsv)?;
        }
        Ok(())
    }
}

impl Execute for FailBox {
    type Error = Error;

    fn execute(
        self,
        _authority: <Account as Identifiable>::Id,
        _wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        iroha_logger::trace!(?self);

        Err(Error::FailBox(self.message))
    }
}

impl Execute for GrantBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let destination_id = self.destination_id.evaluate(wsv, &context)?;
        let object = self.object.evaluate(wsv, &context)?;
        iroha_logger::trace!(?destination_id, ?object, %authority);
        match (destination_id, object) {
            (IdBox::AccountId(account_id), Value::PermissionToken(permission_token)) => {
                Grant::<Account, PermissionToken>::new(permission_token, account_id)
                    .execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(role_id))) => {
                Grant::<Account, RoleId>::new(role_id, account_id).execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::Grant)),
        }
    }
}

impl Execute for RevokeBox {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let destination_id = self.destination_id.evaluate(wsv, &context)?;
        let object = self.object.evaluate(wsv, &context)?;
        iroha_logger::trace!(?destination_id, ?object, %authority);
        match (destination_id, object) {
            (IdBox::AccountId(account_id), Value::PermissionToken(permission_token)) => {
                Revoke::<Account, PermissionToken>::new(permission_token, account_id)
                    .execute(authority, wsv)
            }
            (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(role_id))) => {
                Revoke::<Account, RoleId>::new(role_id, account_id).execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::Revoke)),
        }
    }
}

pub mod prelude {
    //! Re-export important traits and types for glob import `(::*)`
    pub use super::*;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use core::str::FromStr;

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{wsv::World, PeersIds};

    fn world_with_test_domains() -> Result<World> {
        let mut domain = Domain::new(DomainId::from_str("wonderland")?).build();
        let account_id = AccountId::from_str("alice@wonderland")?;
        let (public_key, _) = KeyPair::generate()?.into();
        let account = Account::new(account_id.clone(), [public_key]).build();
        assert!(domain.add_account(account).is_none());
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        assert!(domain
            .add_asset_definition(
                AssetDefinition::store(asset_definition_id).build(),
                account_id
            )
            .is_none());
        Ok(World::with([domain], PeersIds::new()))
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let account_id = AccountId::from_str("alice@wonderland")?;
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        SetKeyValueBox::new(
            IdBox::from(asset_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let asset = wsv.asset(&asset_id)?;
        let metadata: &Metadata = asset.try_as_ref()?;
        let bytes = metadata
            .get(&Name::from_str("Bytes").expect("Valid"))
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
    fn account_metadata() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(account_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id.clone(), &wsv)?;
        let bytes = wsv.map_account(&account_id, |account| {
            account
                .metadata()
                .get(&Name::from_str("Bytes").expect("Valid"))
                .cloned()
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
        let definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(definition_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let bytes = wsv
            .asset_definition_entry(&definition_id)?
            .definition()
            .metadata()
            .get(&Name::from_str("Bytes")?)
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
        let domain_id = DomainId::from_str("wonderland")?;
        let account_id = AccountId::from_str("alice@wonderland")?;
        SetKeyValueBox::new(
            IdBox::from(domain_id.clone()),
            Name::from_str("Bytes")?,
            vec![1_u32, 2_u32, 3_u32],
        )
        .execute(account_id, &wsv)?;
        let bytes = wsv
            .domain(&domain_id)?
            .metadata()
            .get(&Name::from_str("Bytes")?)
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
}
