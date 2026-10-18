//! Immutable encrypted prepared artifacts on the existing private filesystem owner.
//! This codec cannot contain a wallet witness, note opening, membership path or spending key.
use super::*;
use iroha_crypto::encryption::{ChaCha20Poly1305, SymmetricEncryptor};
use iroha_data_model::nexus::{
    PrivateSettlementAuditCapsuleV1, PrivateSettlementCommitteeAuthorityV1,
    PrivateSettlementDeltaV1, PrivateSettlementProofStatementV1,
};
use iroha_fs::{PrivateDirectory, PublishMode};

#[derive(Clone, Copy, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::client::PrivateSettlementPreparedArtifactKeyV1")]
pub(super) struct ArtifactKey {
    pub request: Digest32,
    pub round: Digest32,
    pub ordinal: u8,
}
impl ArtifactKey {
    fn name(self) -> String {
        format!("{}-{:03}.prepared", hex::encode(self.round), self.ordinal)
    }
    fn context_name(self) -> String {
        format!("{}.contexts", hex::encode(self.round))
    }
    fn aad(
        self,
        purpose: &'static str,
    ) -> std::result::Result<Vec<u8>, OneCallPrivateSettlementError> {
        Ok(norito::encode_canonical(&(purpose.to_owned(), self))?)
    }
}
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::client::PrivateSettlementPreparedArtifactV1")]
pub(super) struct Artifact {
    pub key: ArtifactKey,
    pub context_id: Hash,
    pub context_digest: Digest32,
    pub statement: PrivateSettlementProofStatementV1,
    pub proof: Vec<u8>,
    pub delta: PrivateSettlementDeltaV1,
    pub capsule: PrivateSettlementAuditCapsuleV1,
    pub policy: PrivateSettlementAuditPolicyV1,
    pub authority: PrivateSettlementCommitteeAuthorityV1,
    pub retention_height: u64,
}
impl Artifact {
    pub fn prepared(&self) -> AtomicPrivateSettlementPreparedLegV1 {
        AtomicPrivateSettlementPreparedLegV1 {
            statement: self.statement.clone(),
            proof: self.proof.clone(),
            delta: self.delta.clone(),
            audit_capsule: self.capsule.clone(),
        }
    }
    pub fn into_input(
        self,
    ) -> std::result::Result<
        AtomicPrivateSettlementProvisionalLegInputV1,
        OneCallPrivateSettlementError,
    > {
        AtomicPrivateSettlementProvisionalLegInputV1::new(
            AtomicPrivateSettlementPreparedLegV1 {
                statement: self.statement,
                proof: self.proof,
                delta: self.delta,
                audit_capsule: self.capsule,
            },
            self.policy,
            self.authority,
            self.retention_height,
        )
        .map_err(|e| AtomicPrivateSettlementPreparationErrorV1::Wallet(e).into())
    }
    pub fn digest(&self) -> std::result::Result<Digest32, OneCallPrivateSettlementError> {
        let bytes = zeroize::Zeroizing::new(norito::encode_canonical(self)?);
        Ok(domain_digest(
            b"iroha:private-settlement:prepared-artifact:v1\0",
            &[&bytes],
        ))
    }
}
/// Caller-keyed private prepared-artifact store. Files are AEAD-authenticated, written once
/// under exact original round/leg names and never overwritten. Existing private-directory
/// native identity, mode, size, atomic publication and durability rules remain the sole owner.
///
/// Encryption keys stay with the caller; losing the key makes these local artifacts unavailable.
/// Witness plaintext and spending secrets cannot enter this store's closed artifact codec.
pub struct FilePrivateSettlementArtifacts {
    directory: PrivateDirectory,
    cipher: SymmetricEncryptor<ChaCha20Poly1305>,
}
impl FilePrivateSettlementArtifacts {
    /// Open/create an owner-private artifact directory with a caller-retained encryption key.
    /// # Errors
    /// Unsafe directory custody, unavailable I/O or invalid key length.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        key: &[u8; 32],
    ) -> std::result::Result<Self, OneCallPrivateSettlementError> {
        if key.iter().all(|b| *b == 0) {
            return Err(OneCallPrivateSettlementError::Binding);
        }
        Ok(Self {
            directory: PrivateDirectory::open_or_create(path)
                .map_err(OneCallPrivateSettlementError::Storage)?,
            cipher: SymmetricEncryptor::new_with_key(key)
                .map_err(|_| OneCallPrivateSettlementError::Binding)?,
        })
    }
    /// Reopen the exact original all-leg public context. Decode and AEAD custody do not authenticate it;
    /// the caller must reverify it against the independently pinned original native decision.
    pub(super) fn read_context(
        &self,
        key: ArtifactKey,
        maximum: usize,
    ) -> std::result::Result<
        Option<(PrivateSettlementContextsProofV1, usize)>,
        OneCallPrivateSettlementError,
    > {
        let maximum =
            maximum.min(iroha_data_model::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1);
        let limit = maximum
            .checked_add(28)
            .ok_or(OneCallPrivateSettlementError::Capacity)?;
        let Some(envelope) = self
            .directory
            .read_optional(key.context_name(), limit)
            .map_err(OneCallPrivateSettlementError::Storage)?
        else {
            return Ok(None);
        };
        let plaintext = zeroize::Zeroizing::new(
            self.cipher
                .decrypt_easy(
                    &ArtifactKey { ordinal: 0, ..key }.aad("contexts")?,
                    &envelope,
                )
                .map_err(|_| OneCallPrivateSettlementError::Binding)?,
        );
        if plaintext.len() > maximum {
            return Err(OneCallPrivateSettlementError::Capacity);
        }
        Ok(Some((
            PrivateSettlementContextsProofV1::decode_frame(&plaintext)?,
            plaintext.len(),
        )))
    }
    /// Persist a verified original all-leg batch before wallet reservation or proving, under the same round lease.
    /// A failed durable acknowledgement must be reconciled by reading this exact filename first.
    pub(super) fn publish_context(
        &self,
        key: ArtifactKey,
        proof: &PrivateSettlementContextsProofV1,
        maximum: usize,
    ) -> std::result::Result<usize, OneCallPrivateSettlementError> {
        let maximum =
            maximum.min(iroha_data_model::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1);
        let length = norito::canonical_frame_len(proof)?;
        if length > maximum {
            return Err(OneCallPrivateSettlementError::Capacity);
        }
        let bytes = zeroize::Zeroizing::new(norito::encode_canonical(proof)?);
        let ciphertext = self
            .cipher
            .encrypt_easy(&ArtifactKey { ordinal: 0, ..key }.aad("contexts")?, &bytes)
            .map_err(|_| OneCallPrivateSettlementError::Capacity)?;
        self.directory
            .write_atomic(key.context_name(), &ciphertext, PublishMode::CreateNew)
            .map_err(OneCallPrivateSettlementError::Storage)?;
        Ok(length)
    }
    /// Reopen one original encrypted leg and verify its exact request, round and ordinal.
    pub(super) fn read(
        &self,
        key: ArtifactKey,
        maximum: usize,
    ) -> std::result::Result<Option<(Artifact, usize)>, OneCallPrivateSettlementError> {
        let envelope_limit = maximum
            .checked_add(28)
            .ok_or(OneCallPrivateSettlementError::Capacity)?;
        let Some(envelope) = self
            .directory
            .read_optional(key.name(), envelope_limit)
            .map_err(OneCallPrivateSettlementError::Storage)?
        else {
            return Ok(None);
        };
        let aad = key.aad("prepared")?;
        let plaintext = zeroize::Zeroizing::new(
            self.cipher
                .decrypt_easy(aad.as_slice(), envelope.as_slice())
                .map_err(|_| OneCallPrivateSettlementError::Binding)?,
        );
        if plaintext.len() > maximum {
            return Err(OneCallPrivateSettlementError::Capacity);
        }
        let artifact: Artifact = norito::decode_canonical_with_limits(
            &plaintext,
            norito::DecodeLimits::new(
                maximum,
                maximum,
                maximum,
                maximum
                    .checked_mul(4)
                    .ok_or(OneCallPrivateSettlementError::Capacity)?,
                64,
            ),
        )?;
        if artifact.key.request != key.request
            || artifact.key.round != key.round
            || artifact.key.ordinal != key.ordinal
        {
            return Err(OneCallPrivateSettlementError::Binding);
        }
        Ok(Some((artifact, plaintext.len())))
    }
    /// Caller holds the original durable per-round runner lease throughout publication.
    /// An I/O error is deliberately ambiguous; next recovery reads this original name first.
    pub(super) fn publish(
        &self,
        artifact: &Artifact,
        maximum: usize,
    ) -> std::result::Result<usize, OneCallPrivateSettlementError> {
        let length = norito::canonical_frame_len(artifact)?;
        if length > maximum {
            return Err(OneCallPrivateSettlementError::Capacity);
        }
        let bytes = zeroize::Zeroizing::new(norito::encode_canonical(artifact)?);
        let aad = artifact.key.aad("prepared")?;
        let ciphertext = self
            .cipher
            .encrypt_easy(aad.as_slice(), bytes.as_slice())
            .map_err(|_| OneCallPrivateSettlementError::Capacity)?;
        self.directory
            .write_atomic(artifact.key.name(), &ciphertext, PublishMode::CreateNew)
            .map_err(OneCallPrivateSettlementError::Storage)?;
        Ok(length)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::test_support::client_with_base_url;
    use iroha_test_samples::private_settlement::{
        availability_material_fixture_v1, context_fixture,
    };

    fn fixture() -> Artifact {
        let client = client_with_base_url("http://mock.local/".parse().unwrap());
        let (material, _) = availability_material_fixture_v1(client.network_id(), client.account());
        Artifact {
            key: ArtifactKey {
                request: [1; 32],
                round: [2; 32],
                ordinal: 0,
            },
            context_id: Hash::new(b"artifact storage fixture only"),
            context_digest: [6; 32],
            statement: material.statement,
            proof: material.proof,
            delta: material.delta,
            capsule: material.audit_capsule,
            policy: material.audit_policy,
            authority: material.committee_authority,
            retention_height: 500,
        }
    }

    #[test]
    fn private_onecall_original_context_survives_restart_without_replacement_or_artifact_confusion()
    {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("artifacts");
        let key = fixture().key;
        let client = client_with_base_url("http://mock.local/".parse().unwrap());
        let proof = PrivateSettlementContextsProofV1 {
            contexts: vec![context_fixture(client.network_id(), client.account())],
        };
        let maximum = norito::canonical_frame_len(&proof).unwrap();
        let store = FilePrivateSettlementArtifacts::open(&path, &[22; 32]).unwrap();
        assert!(store.read_context(key, maximum).unwrap().is_none());
        assert!(matches!(
            store.publish_context(key, &proof, maximum - 1),
            Err(OneCallPrivateSettlementError::Capacity)
        ));
        store.publish_context(key, &proof, maximum).unwrap();
        let original = std::fs::read(path.join(key.context_name())).unwrap();
        drop(store);
        let reopened = FilePrivateSettlementArtifacts::open(&path, &[22; 32]).unwrap();
        assert_eq!(
            reopened.read_context(key, maximum).unwrap().unwrap().0,
            proof
        );
        let mut changed = proof.clone();
        changed.contexts[0].pool.pool.epoch += 1;
        assert!(reopened.publish_context(key, &changed, maximum).is_err());
        assert_eq!(
            std::fs::read(path.join(key.context_name())).unwrap(),
            original
        );
        assert!(
            reopened
                .read_context(
                    ArtifactKey {
                        request: [7; 32],
                        ..key
                    },
                    maximum
                )
                .is_err()
        );
        std::fs::write(path.join(key.name()), &original).unwrap();
        assert!(
            reopened.read(key, maximum).is_err(),
            "context ciphertext cannot be relabeled as prepared proof artifacts"
        );
        let foreign = FilePrivateSettlementArtifacts::open(&path, &[23; 32]).unwrap();
        assert!(foreign.read_context(key, maximum).is_err());
    }

    #[test]
    fn private_onecall_artifact_custody_reopens_exact_bound_encrypted_original() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("artifacts");
        let store = FilePrivateSettlementArtifacts::open(&path, &[19; 32]).unwrap();
        let artifact = fixture();
        let digest = artifact.digest().unwrap();
        let key = artifact.key;
        let size = norito::canonical_frame_len(&artifact).unwrap();
        assert_eq!(store.publish(&artifact, size).unwrap(), size);
        let bytes = std::fs::read(path.join(key.name())).unwrap();
        assert_ne!(bytes, norito::encode_canonical(&artifact).unwrap());
        drop(store);
        let reopened = FilePrivateSettlementArtifacts::open(&path, &[19; 32]).unwrap();
        let (restored, actual) = reopened.read(key, size).unwrap().unwrap();
        assert_eq!(actual, size);
        assert_eq!(restored.digest().unwrap(), digest);
        assert!(
            reopened.publish(&artifact, size).is_err(),
            "original artifact is never overwritten"
        );
        assert_eq!(std::fs::read(path.join(key.name())).unwrap(), bytes);
        let other_request = ArtifactKey {
            request: [3; 32],
            ..key
        };
        assert!(
            matches!(
                reopened.read(other_request, size),
                Err(OneCallPrivateSettlementError::Binding)
            ),
            "same round filename cannot transfer artifact authority to another request"
        );
        let foreign = FilePrivateSettlementArtifacts::open(&path, &[20; 32]).unwrap();
        assert!(matches!(
            foreign.read(key, size),
            Err(OneCallPrivateSettlementError::Binding)
        ));
    }

    #[test]
    fn private_onecall_artifact_bounds_cover_real_length_without_claiming_valid_proof() {
        // These opaque fixture bytes test custody geometry only, never prover/receipt acceptance.
        let mut artifact = fixture();
        artifact.proof = vec![0xA6; 2_527_280];
        let size = norito::canonical_frame_len(&artifact).unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("artifacts");
        let store = FilePrivateSettlementArtifacts::open(&path, &[21; 32]).unwrap();
        assert!(matches!(
            store.publish(&artifact, size - 1),
            Err(OneCallPrivateSettlementError::Capacity)
        ));
        assert!(store.read(artifact.key, size).unwrap().is_none());
        store.publish(&artifact, size).unwrap();
        let (original, actual) = store.read(artifact.key, size).unwrap().unwrap();
        assert_eq!(actual, size);
        assert_eq!(original.digest().unwrap(), artifact.digest().unwrap());
        assert!(store.read(artifact.key, size - 1).is_err());
        let original_bytes = std::fs::read(path.join(artifact.key.name())).unwrap();
        let mut changed = original_bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(path.join(artifact.key.name()), changed).unwrap();
        assert!(
            store.read(artifact.key, size).is_err(),
            "AEAD rejects corrupted retained originals"
        );
    }
}
