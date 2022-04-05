//! This module contains enumeration of all possible Iroha Special Instructions `Instruction`,
//! generic instruction types and related implementations.
pub mod account;
pub mod asset;
pub mod domain;
pub mod expression;
pub mod permissions;
pub mod query;
pub mod triggers;
pub mod tx;
pub mod world;

pub use error::*;
use eyre::Result;
use iroha_crypto::HashOf;
use iroha_data_model::{expression::prelude::*, isi::*, prelude::*};
use iroha_logger::prelude::*;

use super::{Evaluate, Execute};
use crate::{
    prelude::*,
    wsv::{WorldStateView, WorldTrait},
};

pub mod error {
    //! Errors used in Iroha special instructions and
    //! queries. Instruction execution should fail with a specific
    //! error variant, as opposed to a generic (printable-only)
    //! [`eyre::Report`]. If it is impossible to predict what kind of
    //! error shall be raised, there are types that wrap
    //! [`eyre::Report`].
    use std::{
        error::Error as StdError,
        fmt::{Display, Formatter},
    };

    use iroha_crypto::HashOf;
    use iroha_data_model::{
        fixed::FixedPointOperationError, metadata, prelude::*, MintabilityError,
    };
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use thiserror::Error;

    use super::{query, VersionedCommittedBlock};

    /// Instruction execution error type
    #[derive(Debug, Error)]
    pub enum Error {
        /// Failed to find some entity
        #[error("Failed to find")]
        Find(#[source] Box<FindError>),
        /// Failed to assert type
        #[error("Failed to assert type")]
        Type(#[source] TypeError),
        /// Failed to assert mintability
        #[error("Mintability violation. {0}")]
        Mintability(#[from] MintabilityError),
        /// Failed due to math exception
        #[error("Math error. {0}")]
        Math(#[source] MathError),
        /// Query Error
        #[error("Query failed. {0}")]
        Query(#[source] query::Error),
        /// Metadata Error.
        #[error("Metadata error: {0}")]
        Metadata(#[source] metadata::Error),
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

    // The main reason these are needed is because `FromVariant` can
    // create conflicting implementations if two nodes of the tree of
    // error types have the same type. For example, if query::Error
    // and Error::Validate both have `eyre::Report` the
    // implementations for both will clash.
    impl From<metadata::Error> for Error {
        fn from(err: metadata::Error) -> Self {
            Self::Metadata(err)
        }
    }

    impl From<FindError> for Error {
        fn from(err: FindError) -> Self {
            Self::Find(Box::new(err))
        }
    }

    impl From<query::Error> for Error {
        fn from(err: query::Error) -> Self {
            Self::Query(err)
        }
    }

    /// Enumeration of instructions which can have unsupported variants.
    #[derive(Debug, Clone, Copy)]
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

    impl std::fmt::Display for InstructionType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Debug::fmt(self, f)
        }
    }

    /// Type assertion error
    #[derive(Debug, Clone, Error, Decode, Encode, IntoSchema)]
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
        Domain(DomainId),
        /// Failed to find metadata key
        #[error("Failed to find metadata key")]
        MetadataKey(Name),
        /// Block with supplied parent hash not found. More description in a string.
        #[error("Block not found")]
        Block(#[source] ParentHashNotFound),
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
        #[cfg(feature = "roles")]
        #[error("Failed to find role by id: `{0}`")]
        Role(RoleId),
    }

    /// Type assertion error
    #[derive(Debug, Clone, Error, Copy, PartialEq, Eq)]
    pub enum TypeError {
        /// Asset type assertion error
        #[error("Failed to assert type of asset")]
        Asset(#[source] AssetTypeError),
    }

    impl From<AssetTypeError> for TypeError {
        fn from(err: AssetTypeError) -> Self {
            Self::Asset(err)
        }
    }

    /// Asset type assertion error
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AssetTypeError {
        /// Expected type
        pub expected: AssetValueType,
        /// Type which was discovered
        pub got: AssetValueType,
    }

    impl Display for AssetTypeError {
        #[allow(clippy::use_debug)]
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
                FixedPointOperationError::Overflow => Self::Math(MathError::Overflow),
                FixedPointOperationError::DivideByZero => Self::Math(MathError::DivideByZero),
                FixedPointOperationError::DomainViolation => Self::Math(MathError::DomainViolation),
                FixedPointOperationError::Arithmetic => Self::Math(MathError::Unknown),
            }
        }
    }

    impl From<MathError> for Error {
        fn from(err: MathError) -> Self {
            Self::Math(err)
        }
    }

    /// Block with parent hash not found struct
    #[derive(Debug, Clone, Copy, Decode, Encode, IntoSchema)]
    pub struct ParentHashNotFound(pub HashOf<VersionedCommittedBlock>);

    impl Display for ParentHashNotFound {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Block with parent hash {} not found", self.0)
        }
    }

    impl StdError for ParentHashNotFound {}
}

impl<W: WorldTrait> Execute<W> for Instruction {
    type Error = Error;

    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
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

impl<W: WorldTrait> Execute<W> for RegisterBox {
    type Error = Error;

    #[log]
    fn execute(self, authority: AccountId, wsv: &WorldStateView<W>) -> Result<(), Self::Error> {
        let context = Context::new();

        match self.object.evaluate(wsv, &context)? {
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
            RegistrableBox::Trigger(trigger) => {
                Register::<Trigger>::new(*trigger).execute(authority, wsv)
            }
            #[cfg(feature = "roles")]
            RegistrableBox::Role(role) => Register::<Role>::new(*role).execute(authority, wsv),
            _ => Err(Error::Unsupported(InstructionType::Register)),
        }
    }
}

impl<W: WorldTrait> Execute<W> for UnregisterBox {
    type Error = Error;

    #[log]
    fn execute(self, authority: AccountId, wsv: &WorldStateView<W>) -> Result<(), Self::Error> {
        let context = Context::new();
        match self.object_id.evaluate(wsv, &context)? {
            IdBox::AccountId(account_id) => {
                Unregister::<Account>::new(account_id).execute(authority, wsv)
            }
            IdBox::AssetDefinitionId(asset_definition_id) => {
                Unregister::<AssetDefinition>::new(asset_definition_id).execute(authority, wsv)
            }
            IdBox::DomainId(domain_id) => {
                Unregister::<Domain>::new(domain_id).execute(authority, wsv)
            }
            IdBox::PeerId(peer_id) => Unregister::<Peer>::new(peer_id).execute(authority, wsv),
            _ => Err(Error::Unsupported(InstructionType::Unregister)),
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
    ) -> Result<(), Self::Error> {
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
            _ => Err(Error::Unsupported(InstructionType::Mint)),
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
    ) -> Result<(), Self::Error> {
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
            _ => Err(Error::Unsupported(InstructionType::Burn)),
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
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let source_asset_id = match self.source_id.evaluate(wsv, &context)? {
            IdBox::AssetId(source_asset_id) => source_asset_id,
            _ => return Err(Error::Unsupported(InstructionType::Transfer)),
        };

        let quantity = match self.object.evaluate(wsv, &context)? {
            Value::U32(quantity) => quantity,
            _ => return Err(Error::Unsupported(InstructionType::Transfer)),
        };

        match self.destination_id.evaluate(wsv, &context)? {
            IdBox::AssetId(destination_asset_id) => {
                Transfer::<Asset, u32, Asset>::new(source_asset_id, quantity, destination_asset_id)
                    .execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::Transfer)),
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
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let key = self.key.evaluate(wsv, &context)?;
        let value = self.value.evaluate(wsv, &context)?;
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

impl<W: WorldTrait> Execute<W> for RemoveKeyValueBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        let key = self.key.evaluate(wsv, &context)?;
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

impl<W: WorldTrait> Execute<W> for If {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        if self.condition.evaluate(wsv, &context)? {
            self.then.execute(authority, wsv)?;
        } else if let Some(otherwise) = self.otherwise {
            otherwise.execute(authority, wsv)?;
        }

        Ok(())
    }
}

impl<W: WorldTrait> Execute<W> for Pair {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Self::Error> {
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
    ) -> Result<(), Self::Error> {
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
    ) -> Result<(), Self::Error> {
        Err(Error::FailBox(self.message))
    }
}

impl<W: WorldTrait> Execute<W> for GrantBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Self::Error> {
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
            _ => Err(Error::Unsupported(InstructionType::Grant)),
        }
    }
}

impl<W: WorldTrait> Execute<W> for RevokeBox {
    type Error = Error;

    #[log]
    fn execute(
        self,
        authority: <Account as Identifiable>::Id,
        wsv: &WorldStateView<W>,
    ) -> Result<(), Self::Error> {
        let context = Context::new();
        match (
            self.destination_id.evaluate(wsv, &context)?,
            self.object.evaluate(wsv, &context)?,
        ) {
            (IdBox::AccountId(account_id), Value::PermissionToken(permission_token)) => {
                Revoke::<Account, PermissionToken>::new(permission_token, account_id)
                    .execute(authority, wsv)
            }
            #[cfg(feature = "roles")]
            (IdBox::AccountId(account_id), Value::Id(IdBox::RoleId(role_id))) => {
                Revoke::<Account, RoleId>::new(role_id, account_id).execute(authority, wsv)
            }
            _ => Err(Error::Unsupported(InstructionType::Revoke)),
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

    use core::str::FromStr;

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{wsv::World, PeersIds};

    fn world_with_test_domains() -> Result<World> {
        let mut domain = Domain::new(DomainId::from_str("wonderland")?).build();
        let account_id = AccountId::from_str("alice@wonderland")?;
        let key_pair = KeyPair::generate()?;
        let account = Account::new(account_id.clone(), [key_pair.public_key]).build();
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
        let wsv = WorldStateView::<World>::new(world_with_test_domains()?);
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
