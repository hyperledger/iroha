//! Signed execution scope of an independent Sumeragi root ledger.

use iroha_model_base::topology::DataSpaceId;
use iroha_schema::IntoSchema;
use iroha_sumeragi::{
    crypto::Crypto,
    preimage::{InstanceKind, instance_id},
    types::Hash32,
};
use norito::codec::{Decode, Encode};

use super::ValidationError;
use crate::{DeriveJsonSerialize, NetworkId};
mod json;

/// Immutable root identity selected by signed genesis, never by node-local configuration.
///
/// A dataspace root has its own genesis, State and native instance. Its full 64-bit dataspace
/// identifier and parent network are committed by that genesis; the native root index is zero.
/// The identifier must not be narrowed into the protocol's 32-bit instance index.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::block::consensus::SumeragiRootScope")]
#[norito(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SumeragiRootScope {
    /// The global ledger owns the universal execution scope.
    Global,
    /// An independent private ledger attached to one exact parent network and dataspace.
    Dataspace {
        /// Exact parent genesis identity; resets create a different attachment authority.
        parent_network_id: NetworkId,
        /// Full parent-assigned dataspace identifier, which must be non-universal.
        dataspace_id: DataSpaceId,
    },
}

impl SumeragiRootScope {
    /// Validate the complete signed scope.
    ///
    /// # Errors
    /// A private root cannot claim the universal dataspace.
    pub fn validate(self) -> Result<(), ValidationError> {
        if matches!(self, Self::Dataspace { dataspace_id, .. } if dataspace_id == DataSpaceId::UNIVERSAL)
        {
            return Err(ValidationError::InvalidRootScope);
        }
        Ok(())
    }

    /// Native consensus instance kind of this root.
    #[must_use]
    pub const fn instance_kind(self) -> InstanceKind {
        match self {
            Self::Global => InstanceKind::Global,
            Self::Dataspace { .. } => InstanceKind::Dataspace,
        }
    }

    /// Execution scope owned by the root's lane zero.
    #[must_use]
    pub const fn dataspace_id(self) -> DataSpaceId {
        match self {
            Self::Global => DataSpaceId::UNIVERSAL,
            Self::Dataspace { dataspace_id, .. } => dataspace_id,
        }
    }

    /// Derive a native instance from an independently authenticated genesis and chain label.
    ///
    /// The caller must establish that `network` is the hash of genesis carrying this scope.
    /// Parent registration authenticates that binding without exporting private genesis bodies.
    ///
    /// # Errors
    /// The signed scope is invalid.
    pub fn instance_id(
        self,
        crypto: &dyn Crypto,
        network: NetworkId,
        chain_id: &str,
    ) -> Result<Hash32, ValidationError> {
        self.validate()?;
        Ok(instance_id(
            crypto,
            &Hash32(*network.as_bytes()),
            chain_id.as_bytes(),
            self.instance_kind(),
            0,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};

    fn parent() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"parent")))
    }

    #[test]
    fn scope_preserves_full_dataspace_identity_in_both_codecs() {
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: parent(),
            dataspace_id: DataSpaceId::new(u64::MAX),
        };
        scope.validate().unwrap();
        assert_eq!(scope.dataspace_id(), DataSpaceId::new(u64::MAX));
        assert_eq!(scope.instance_kind(), InstanceKind::Dataspace);
        let bytes = norito::encode_canonical(&scope).unwrap();
        assert_eq!(
            norito::decode_canonical::<SumeragiRootScope>(&bytes).unwrap(),
            scope
        );
        let json = norito::json::to_json(&scope).unwrap();
        assert_eq!(
            norito::json::from_str::<SumeragiRootScope>(&json).unwrap(),
            scope
        );
        assert_eq!(
            SumeragiRootScope::Global.dataspace_id(),
            DataSpaceId::UNIVERSAL
        );
        assert_eq!(
            SumeragiRootScope::Global.instance_kind(),
            InstanceKind::Global
        );
    }

    #[test]
    fn private_root_cannot_claim_the_universal_scope() {
        assert_eq!(
            SumeragiRootScope::Dataspace {
                parent_network_id: parent(),
                dataspace_id: DataSpaceId::UNIVERSAL,
            }
            .validate(),
            Err(ValidationError::InvalidRootScope)
        );
    }
}
