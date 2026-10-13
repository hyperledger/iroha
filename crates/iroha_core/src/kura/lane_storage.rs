//! Exact lane-instance storage identity, independent of catalog display metadata.
//!
//! These values identify objects; they grant neither active-lane admission nor
//! historical execution authority. Kura installs them only from authenticated
//! State/catalog recovery and retains them in its durable reference journal.

use super::*;

const INSTANCE_PATH_DOMAIN: &[u8] = b"iroha:kura:lane-storage-instance:v1\0";

/// Exact lane-instance storage identity. This value is a locator, not write authority.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::kura::LaneStorageIdentity")]
pub struct LaneStorageIdentity {
    pub(crate) network_id: NetworkId,
    pub(crate) lane_id: LaneId,
    pub(crate) dataspace_id: DataSpaceId,
    pub(crate) incarnation: Hash,
    pub(crate) activation_height: u64,
}

impl LaneStorageIdentity {
    /// Construct an exact storage locator from all five identity components.
    /// This grants no authenticated recovery, execution, or write authority.
    #[must_use]
    pub fn new(
        network_id: NetworkId,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        incarnation: Hash,
        activation_height: u64,
    ) -> Self {
        Self {
            network_id,
            lane_id,
            dataspace_id,
            incarnation,
            activation_height,
        }
    }

    fn key(self) -> String {
        let encoded = self.encode();
        hex::encode(Hash::new_from_chunks(&[INSTANCE_PATH_DOMAIN, &encoded]).as_ref())
    }

    pub(super) fn blocks_relative(self) -> String {
        format!("blocks/instances/{}", self.key())
    }

    /// Resolve this exact instance beneath a Kura store root.
    #[must_use]
    pub fn blocks_dir(self, root: impl AsRef<Path>) -> PathBuf {
        root.as_ref().join(self.blocks_relative())
    }
}

/// One exact immutable physical identity; catalog display metadata is absent.
/// Cloning this data does not acquire a writer, pin, or publication capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LaneStorageEntry {
    pub(super) identity: LaneStorageIdentity,
}

impl std::ops::Deref for LaneStorageEntry {
    type Target = LaneStorageIdentity;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::DecodeAll;

    fn identity() -> LaneStorageIdentity {
        LaneStorageIdentity::new(
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"network"))),
            LaneId::new(1),
            DataSpaceId::new(2),
            Hash::new(b"incarnation"),
            3,
        )
    }

    #[test]
    fn immutable_paths_commit_every_identity_component() {
        let expected = identity();
        let mut variants = [expected; 5];
        variants[0].network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"other-network"),
        ));
        variants[1].lane_id = LaneId::new(2);
        variants[2].dataspace_id = DataSpaceId::new(3);
        variants[3].incarnation = Hash::new(b"other-incarnation");
        variants[4].activation_height = 4;
        for changed in variants {
            assert_ne!(expected.blocks_relative(), changed.blocks_relative());
        }
        let bytes = expected.encode();
        let decoded = LaneStorageIdentity::decode_all(&mut bytes.as_slice())
            .expect("exact identity roundtrip");
        assert_eq!(decoded, expected);
        assert_eq!(decoded.blocks_relative(), expected.blocks_relative());
    }

    #[test]
    fn active_entry_and_retained_identity_resolve_the_same_exact_object() {
        let identity = identity();
        let entry = LaneStorageEntry { identity };
        assert_eq!(
            entry.blocks_dir("root"),
            identity.blocks_dir(Path::new("root"))
        );
    }
}
