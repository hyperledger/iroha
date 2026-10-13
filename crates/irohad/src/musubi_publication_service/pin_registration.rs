//! Exact finalized pin-registration recovery for a private Musubi coordinator.
//!
//! This is a read-only resume gate. It neither signs nor queues a transaction, and it cannot
//! replace the durable signed-intent outbox that must be committed before queue admission.
// TODO: Bind the configured paid-pin policy and exact fee quote to a durable signed-intent
// outbox, purpose-qualified signer and canonical Queue admission before enabling coordinator
// effects; this reader alone does not make stock publication operational.
use super::{
    MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    MusubiPublicationPrivateServiceContextV1, finality::validate_finalized_block_wire,
};
use iroha_core::state::{State, StateReadOnly as _, WorldReadOnly, WorldStateSnapshot as _};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::sorafs::RegisterPinManifest,
    musubi::MusubiArchiveCommitmentV1,
    sorafs::pin_registry::{
        ManifestDigest, ManifestRootCid, PinManifestRecord, PinPolicy, PinStatus, StorageClass,
    },
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};
use mv::storage::StorageReadOnly as _;
use sorafs_manifest::{ManifestV1, StorageClass as ManifestStorageClass};
use std::{num::NonZeroUsize, sync::Arc};

/// Exact signed transaction and finalized height needed to resume one paid pin registration.
///
/// The transaction must be the same canonical signed V1 wire admitted by the source block. An
/// intent hash alone cannot recover the signer proof or distinguish an unsuccessful inclusion.
#[derive(Clone, Debug)]
pub struct MusubiPublicationFinalizedPinRegistrationQueryV1 {
    /// Closed query schema version; must equal one.
    pub version: u8,
    /// Source archive's independently authenticated finalized registration.
    pub source: MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    /// Exact signed sole-`RegisterPinManifest` transaction retained by the outbox.
    pub transaction: SignedTransaction,
    /// Manifest digest derived from the canonical payload before signing.
    pub manifest_digest: ManifestDigest,
    /// Height containing the successful registration output.
    pub finalized_height: u64,
}

/// Redacted finality/replay failure for one signed pin registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MusubiPublicationFinalizedPinRegistrationReadErrorV1 {
    /// Original local allocation admission has not completed; retry the same read.
    Deferred(iroha_core::execution_attempt::ExecutionDeferred),
    /// The named height or source snapshot is ahead of this node's finalized view.
    LocallyAhead,
    /// The signed intent, output, finalized block, or current pin record differs.
    Invalid,
}
impl core::fmt::Display for MusubiPublicationFinalizedPinRegistrationReadErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Deferred(_) => "finalized history read is waiting for local capacity",
            Self::LocallyAhead => "finalized Musubi pin registration is ahead of local state",
            Self::Invalid => "finalized Musubi pin registration is invalid",
        })
    }
}
impl std::error::Error for MusubiPublicationFinalizedPinRegistrationReadErrorV1 {}
impl From<iroha_core::execution_attempt::ExecutionDeferred>
    for MusubiPublicationFinalizedPinRegistrationReadErrorV1
{
    fn from(error: iroha_core::execution_attempt::ExecutionDeferred) -> Self {
        Self::Deferred(error)
    }
}
impl From<iroha_core::execution_attempt::ExecutionAttemptError<iroha_core::kura::Error>>
    for MusubiPublicationFinalizedPinRegistrationReadErrorV1
{
    fn from(
        error: iroha_core::execution_attempt::ExecutionAttemptError<iroha_core::kura::Error>,
    ) -> Self {
        match error {
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(error) => {
                Self::Deferred(error)
            }
            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_) => Self::Invalid,
        }
    }
}

/// Daemon-owned same-view finality and current-state reader for pin-registration recovery.
///
/// The expected submitter must come from the deployment's non-secret configured pin authority;
/// the signer credential itself remains in runtime custody.
pub struct MusubiPublicationFinalizedPinRegistrationReaderV1 {
    network_id: NetworkId,
    pin_authority: AccountId,
    state: Arc<State>,
    archive_reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
}
impl core::fmt::Debug for MusubiPublicationFinalizedPinRegistrationReaderV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MusubiPublicationFinalizedPinRegistrationReaderV1")
            .field("network_id", &self.network_id)
            .finish_non_exhaustive()
    }
}
impl MusubiPublicationPrivateServiceContextV1 {
    /// Bind pin recovery to this daemon's live State/Kura handles and configured authority.
    #[must_use]
    pub fn finalized_pin_registration_reader(
        &self,
        pin_authority: AccountId,
    ) -> MusubiPublicationFinalizedPinRegistrationReaderV1 {
        MusubiPublicationFinalizedPinRegistrationReaderV1 {
            network_id: self.network_id(),
            pin_authority,
            state: self.state(),
            archive_reader: self.finalized_archive_registration_reader(),
        }
    }
}
impl MusubiPublicationFinalizedPinRegistrationReaderV1 {
    /// Recover a successful exact signed pin transaction and its current authoritative record.
    ///
    /// The source archive, pin output, and pin record are checked in one State query view. Both
    /// named blocks must have exact Kura Sumeragi finality proofs and result-bearing executed-block
    /// commitments. A failed transaction, alternate signature wire, retired pin, or changed
    /// current record is never treated as completion. State-root publication is a separate gate.
    ///
    /// # Errors
    /// Returns `LocallyAhead` only for a future source snapshot or pin height. All other missing,
    /// malformed, substituted, or unsuccessful evidence is permanently invalid.
    pub fn read_current_pin(
        &self,
        query: &MusubiPublicationFinalizedPinRegistrationQueryV1,
    ) -> Result<PinManifestRecord, MusubiPublicationFinalizedPinRegistrationReadErrorV1> {
        use MusubiPublicationFinalizedPinRegistrationReadErrorV1::{Invalid, LocallyAhead};
        if query.version != 1
            || query.source.network_id != self.network_id
            || query.finalized_height == 0
            || query.finalized_height < query.source.registration.registered_at_height
        {
            return Err(Invalid);
        }
        let view = self.state.query_view();
        let archive = self
            .archive_reader
            .read_current_archive_in_view(&query.source, &view)
            .map_err(|error| match error {
                super::MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead => {
                    LocallyAhead
                }
                super::MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Deferred(
                    error,
                ) => MusubiPublicationFinalizedPinRegistrationReadErrorV1::Deferred(error),
                super::MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Invalid => Invalid,
            })?;
        let manifest = validate_signed_pin_intent(
            &self.network_id,
            &self.pin_authority,
            &archive.commitment,
            &query.transaction,
            query.manifest_digest,
        )?;
        let height = usize::try_from(query.finalized_height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(Invalid)?;
        if height.get() > view.block_hashes().len() {
            return Err(LocallyAhead);
        }
        let canonical_hash = view
            .block_hashes()
            .get(height.get() - 1)
            .copied()
            .ok_or(Invalid)?;
        let block = view
            .kura()
            .get_block(height, &view.execution_budget())?
            .ok_or(Invalid)?;
        if !validate_finalized_block_wire(
            &view,
            &self.network_id,
            query.finalized_height,
            canonical_hash,
            &block,
        )? || block.validate_output_merkle_cache().is_err()
            || !exact_successful_pin_transaction(&query.transaction, &block)?
        {
            return Err(Invalid);
        }
        let record = view
            .world()
            .pin_manifests()
            .get(&query.manifest_digest)
            .ok_or(Invalid)?;
        if !pin_record_matches_intent(
            record,
            &manifest,
            &self.pin_authority,
            query.manifest_digest,
        ) {
            return Err(Invalid);
        }
        Ok(record.clone())
    }
}

pub(super) fn validate_signed_pin_intent(
    network_id: &NetworkId,
    authority: &AccountId,
    archive: &MusubiArchiveCommitmentV1,
    transaction: &SignedTransaction,
    expected_digest: ManifestDigest,
) -> Result<ManifestV1, MusubiPublicationFinalizedPinRegistrationReadErrorV1> {
    use MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid;
    if transaction.network_id() != Some(network_id)
        || transaction.authority() != authority
        || !transaction.metadata().is_empty()
        || transaction.attachments().is_some()
        || transaction.multisig_signatures().is_some()
        || transaction.fee_payment_intent().sponsor_program().is_some()
        || transaction.fee_payment_intent().validate().is_err()
    {
        return Err(Invalid);
    }
    let signer = transaction.authority().try_signatory().ok_or(Invalid)?;
    let hash = iroha_crypto::HashOf::try_new(transaction.payload())
        .map_err(|error| codec_refusal(&error))?;
    iroha_crypto::verify_signature_borrowed(&transaction.signature().0, signer, hash.as_ref())
        .map_err(|_| Invalid)?;
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(Invalid);
    };
    let [instruction] = instructions.as_ref() else {
        return Err(Invalid);
    };
    let Some(register) = instruction.as_any().downcast_ref::<RegisterPinManifest>() else {
        return Err(Invalid);
    };
    if register.alias.is_some() || register.successor_of.is_some() {
        return Err(Invalid);
    }
    let manifest = sorafs_manifest::decode_manifest_v1_canonical(&register.manifest_payload)
        .map_err(manifest_codec_refusal)?;
    if ManifestDigest::from_manifest(&manifest).map_err(|error| codec_refusal(&error))?
        != expected_digest
    {
        return Err(Invalid);
    }
    validate_pin_manifest(&manifest, archive)?;
    Ok(manifest)
}

/// The sole exact archive-to-manifest relation, shared by preparation and signed readback.
pub(super) fn validate_pin_manifest(
    manifest: &ManifestV1,
    archive: &MusubiArchiveCommitmentV1,
) -> Result<(), MusubiPublicationFinalizedPinRegistrationReadErrorV1> {
    use MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid;
    if manifest.root_cid.as_slice() != archive.root_cid.as_bytes()
        || manifest.chunking.profile_id.0 != archive.chunker.profile_id
        || manifest.chunking.namespace != archive.chunker.namespace
        || manifest.chunking.name != archive.chunker.name
        || manifest.chunking.semver != archive.chunker.semver
        || manifest.chunking.multihash_code != archive.chunker.multihash_code
        || manifest.chunk_digest_sha3_256 != *archive.chunk_plan_digest.as_bytes()
        || manifest.por_root != *archive.por_root.as_bytes()
        || manifest.content_length != archive.content_length
        || manifest.car_digest != *archive.car_digest.as_bytes()
        || manifest.car_size != archive.car_size
    {
        return Err(Invalid);
    }
    Ok(())
}

pub(super) fn manifest_codec_refusal(
    error: sorafs_manifest::ManifestDecodeError,
) -> MusubiPublicationFinalizedPinRegistrationReadErrorV1 {
    match error {
        sorafs_manifest::ManifestDecodeError::Decode { source }
        | sorafs_manifest::ManifestDecodeError::CanonicalEncoding { source } => {
            codec_refusal(&source)
        }
        _ => MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid,
    }
}

pub(super) fn codec_refusal(
    error: &norito::Error,
) -> MusubiPublicationFinalizedPinRegistrationReadErrorV1 {
    use MusubiPublicationFinalizedPinRegistrationReadErrorV1::{Deferred, Invalid};
    if matches!(error, norito::Error::AllocationFailed { .. }) {
        Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
    } else if norito::core::decode_error_matches_active_limits(error) {
        Deferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into())
    } else {
        Invalid
    }
}

fn exact_successful_pin_transaction(
    expected: &SignedTransaction,
    block: &iroha_data_model::block::SignedBlock,
) -> Result<bool, MusubiPublicationFinalizedPinRegistrationReadErrorV1> {
    let expected_hash = expected
        .try_hash_as_entrypoint()
        .map_err(|error| codec_refusal(&error))?;
    let expected_wire = expected
        .wire_plan_v1()
        .map_err(|error| codec_refusal(&error))?
        .into_vec_bounded(128 * 1024)
        .map_err(|error| codec_refusal(&error))?;
    let mut found = false;
    for (input_index, entrypoint) in block.network_entrypoints().enumerate() {
        let transaction = match entrypoint {
            TransactionEntrypoint::External(transaction) => transaction,
            TransactionEntrypoint::SealedReveal(reveal) => {
                if reveal
                    .signed_transaction()
                    .try_hash_as_entrypoint()
                    .map_err(|error| codec_refusal(&error))?
                    == expected_hash
                {
                    return Ok(false);
                }
                continue;
            }
            TransactionEntrypoint::SealedCommitment(_) => continue,
        };
        if transaction
            .try_hash_as_entrypoint()
            .map_err(|error| codec_refusal(&error))?
            != expected_hash
        {
            continue;
        }
        let Some((_, output)) = u32::try_from(input_index)
            .ok()
            .and_then(|index| block.network_output_at(index))
        else {
            return Ok(false);
        };
        if found || output.result.is_err() {
            return Ok(false);
        }
        let actual = transaction
            .wire_plan_v1()
            .map_err(|error| codec_refusal(&error))?
            .into_vec_bounded(128 * 1024)
            .map_err(|error| codec_refusal(&error))?;
        if actual != expected_wire {
            return Ok(false);
        }
        found = true;
    }
    Ok(found)
}

fn pin_record_matches_intent(
    record: &PinManifestRecord,
    manifest: &ManifestV1,
    authority: &AccountId,
    digest: ManifestDigest,
) -> bool {
    let Ok(root_cid) = ManifestRootCid::try_from_slice(&manifest.root_cid) else {
        return false;
    };
    let storage_class = match manifest.pin_policy.storage_class {
        ManifestStorageClass::Hot => StorageClass::Hot,
        ManifestStorageClass::Warm => StorageClass::Warm,
        ManifestStorageClass::Cold => StorageClass::Cold,
    };
    record.digest == digest
        && record.submitted_by == *authority
        && record.root_cid == root_cid
        && record.chunker.profile_id == manifest.chunking.profile_id.0
        && record.chunker.namespace == manifest.chunking.namespace
        && record.chunker.name == manifest.chunking.name
        && record.chunker.semver == manifest.chunking.semver
        && record.chunker.multihash_code == manifest.chunking.multihash_code
        && record.chunk_digest_sha3_256 == manifest.chunk_digest_sha3_256
        && record.por_root == manifest.por_root
        && record.content_length == manifest.content_length
        && record.policy
            == PinPolicy {
                min_replicas: manifest.pin_policy.min_replicas,
                storage_class,
                retention_epoch: manifest.pin_policy.retention_epoch,
            }
        && record.alias.is_none()
        && record.successor_of.is_none()
        && record
            .pin_fee_payment
            .as_ref()
            .is_some_and(|payment| payment.paid_by == *authority)
        && !matches!(record.status, PinStatus::Retired(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{block::BlockBuilder, tx::AcceptedTransaction};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        ValidationFail,
        asset::AssetDefinitionId,
        block::{
            BlockHeader, SignedBlock,
            execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        },
        isi::InstructionBox,
        musubi::MusubiContentDigestV1,
        parameter::ExecutionOutputPolicyV1,
        sorafs::pin_registry::{ChunkerProfileHandle, PinFeePayment},
        transaction::{
            DataTriggerSequence, FeePaymentIntent, TransactionBuilder, TransactionResultInner,
            error::TransactionRejectionReason,
        },
    };
    use iroha_model_base::{domain::DomainId, metadata::Metadata};
    use iroha_primitives::numeric::Quantity;
    use sorafs_manifest::{DagCodecId, ManifestBuilder, PinPolicy as ManifestPinPolicy, ProfileId};
    use std::borrow::Cow;

    fn fixture() -> (
        NetworkId,
        AccountId,
        MusubiArchiveCommitmentV1,
        ManifestV1,
        KeyPair,
    ) {
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x15; 32]),
        ));
        let key = KeyPair::try_from_seed(vec![0x37; 32], Algorithm::Ed25519).expect("test key");
        let authority = AccountId::new(key.public_key().clone());
        let root = ManifestRootCid::from_blake3_digest([0x51; 32]).expect("root");
        let manifest = ManifestBuilder::new()
            .root_cid(root.as_bytes().to_vec())
            .dag_codec(DagCodecId(sorafs_manifest::MANIFEST_DAG_CODEC))
            .chunking_from_registry(ProfileId(1))
            .chunk_digest_sha3_256([0x55; 32])
            .por_root([0x53; 32])
            .content_length(1024)
            .car_digest([0x54; 32])
            .car_size(2048)
            .pin_policy(ManifestPinPolicy {
                min_replicas: 3,
                storage_class: ManifestStorageClass::Hot,
                retention_epoch: 42,
            })
            .build()
            .expect("manifest");
        let commitment = MusubiArchiveCommitmentV1 {
            root_cid: root,
            chunker: ChunkerProfileHandle {
                profile_id: manifest.chunking.profile_id.0,
                namespace: manifest.chunking.namespace.clone(),
                name: manifest.chunking.name.clone(),
                semver: manifest.chunking.semver.clone(),
                multihash_code: manifest.chunking.multihash_code,
            },
            chunk_plan_digest: MusubiContentDigestV1::new([0x55; 32]),
            por_root: MusubiContentDigestV1::new(manifest.por_root),
            content_length: manifest.content_length,
            car_digest: MusubiContentDigestV1::new(manifest.car_digest),
            car_size: manifest.car_size,
            bundle_digest: MusubiContentDigestV1::new([0x56; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x57; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x58; 32]),
            file_count: 1,
            chunk_count: 1,
        };
        (network, authority, commitment, manifest, key)
    }

    fn signed_pin(
        network: NetworkId,
        authority: AccountId,
        key: &KeyPair,
        manifest: &ManifestV1,
        duplicate: bool,
    ) -> SignedTransaction {
        let instruction = InstructionBox::from(RegisterPinManifest::new(
            manifest.encode().expect("encode manifest"),
            None,
            None,
        ));
        let mut instructions = vec![instruction.clone()];
        if duplicate {
            instructions.push(instruction);
        }
        TransactionBuilder::new(
            network,
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .sign(key.private_key())
    }

    fn result_bearing_block(transaction: SignedTransaction, success: bool) -> SignedBlock {
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(transaction));
        let mut block: SignedBlock = BlockBuilder::new(vec![accepted])
            .chain(0, None)
            .sign(
                KeyPair::try_from_seed(vec![0x44; 32], Algorithm::Ed25519)
                    .expect("block test key")
                    .private_key(),
            )
            .unpack(|_| {})
            .into();
        let result = if success {
            TransactionResultInner::Ok(DataTriggerSequence::default())
        } else {
            TransactionResultInner::Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("rejected pin fixture".to_owned()),
            ))
        };
        block
            .set_execution_outputs(
                vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                    input_index: 0,
                    result: result.into(),
                    completions: Vec::new(),
                })],
                u64::from(success),
                std::collections::BTreeMap::default(),
                block.axt_envelopes().unwrap_or_default().to_vec(),
                block.axt_policy_snapshot().cloned().unwrap_or_default(),
                block
                    .axt_transitioned_dataspaces()
                    .cloned()
                    .unwrap_or_default(),
                &ExecutionOutputPolicyV1::bootstrap().limits(),
            )
            .expect("fixture output matches immutable input");
        block
    }

    #[test]
    fn signed_pin_preflight_binds_authority_network_sole_instruction_and_archive() {
        let (network, authority, archive, manifest, key) = fixture();
        let digest = ManifestDigest::from_manifest(&manifest).expect("manifest digest");
        let transaction = signed_pin(network, authority.clone(), &key, &manifest, false);
        assert_eq!(
            validate_signed_pin_intent(&network, &authority, &archive, &transaction, digest)
                .expect("exact signed pin"),
            manifest
        );
        assert_eq!(
            validate_signed_pin_intent(
                &network,
                &authority,
                &archive,
                &signed_pin(network, authority.clone(), &key, &manifest, true),
                digest,
            ),
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid)
        );
        let mut wrong_archive = archive.clone();
        wrong_archive.car_size += 1;
        assert_eq!(
            validate_signed_pin_intent(&network, &authority, &wrong_archive, &transaction, digest,),
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid)
        );
        let mut wrong_chunk_plan = archive.clone();
        wrong_chunk_plan.chunk_plan_digest = MusubiContentDigestV1::new([0x52; 32]);
        assert_eq!(
            validate_signed_pin_intent(
                &network,
                &authority,
                &wrong_chunk_plan,
                &transaction,
                digest,
            ),
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid)
        );
        assert_eq!(
            validate_signed_pin_intent(
                &network,
                &authority,
                &archive,
                &transaction,
                ManifestDigest::new([0x90; 32]),
            ),
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid)
        );
        let foreign_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x17; 32])),
        );
        assert_eq!(
            validate_signed_pin_intent(
                &foreign_network,
                &authority,
                &archive,
                &transaction,
                digest,
            ),
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid)
        );
        let foreign_key =
            KeyPair::try_from_seed(vec![0x38; 32], Algorithm::Ed25519).expect("foreign key");
        let foreign_authority = AccountId::new(foreign_key.public_key().clone());
        let wrong_signature = transaction
            .clone()
            .with_authority(foreign_authority.clone());
        assert_eq!(
            validate_signed_pin_intent(
                &network,
                &foreign_authority,
                &archive,
                &wrong_signature,
                digest,
            ),
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Invalid)
        );
    }

    #[test]
    fn original_pin_codec_refusal_is_local_deferred_and_same_wire_retries() {
        let (network, authority, archive, manifest, key) = fixture();
        let digest = ManifestDigest::from_manifest(&manifest).unwrap();
        let transaction = signed_pin(network, authority.clone(), &key, &manifest, false);
        let wire = transaction.encode_wire_v1().unwrap();
        let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
        let refused = norito::with_decode_limits_scope(zero, || {
            validate_signed_pin_intent(&network, &authority, &archive, &transaction, digest)
        });
        assert!(matches!(
            refused,
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Deferred(_))
        ));
        assert_eq!(transaction.encode_wire_v1().unwrap(), wire);
        assert_eq!(
            validate_signed_pin_intent(&network, &authority, &archive, &transaction, digest)
                .unwrap(),
            manifest
        );
        // This block exercises the existing output matcher only, not a native-finality proof.
        let block = result_bearing_block(transaction.clone(), true);
        let refused = norito::with_decode_limits_scope(zero, || {
            exact_successful_pin_transaction(&transaction, &block)
        });
        assert!(matches!(
            refused,
            Err(MusubiPublicationFinalizedPinRegistrationReadErrorV1::Deferred(_))
        ));
        assert!(exact_successful_pin_transaction(&transaction, &block).unwrap());
    }

    #[test]
    fn manifest_codec_refusal_preserves_allocation_and_rejects_invalid_wire() {
        use MusubiPublicationFinalizedPinRegistrationReadErrorV1::{Deferred, Invalid};
        use sorafs_manifest::ManifestDecodeError;

        for error in [
            ManifestDecodeError::Decode {
                source: norito::Error::AllocationFailed { bytes: 64 },
            },
            ManifestDecodeError::CanonicalEncoding {
                source: norito::Error::AllocationFailed { bytes: 64 },
            },
        ] {
            assert_eq!(
                manifest_codec_refusal(error),
                Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
            );
        }
        for error in [
            ManifestDecodeError::NonCanonicalEncoding,
            ManifestDecodeError::Decode {
                source: norito::Error::LengthMismatch,
            },
            ManifestDecodeError::CanonicalEncoding {
                source: norito::Error::LengthMismatch,
            },
        ] {
            assert_eq!(manifest_codec_refusal(error), Invalid);
        }
    }

    #[test]
    fn current_pin_record_rejects_retirement_fee_substitution_and_manifest_changes() {
        let (_, authority, archive, manifest, _) = fixture();
        let digest = ManifestDigest::from_manifest(&manifest).expect("manifest digest");
        let policy = PinPolicy {
            min_replicas: manifest.pin_policy.min_replicas,
            storage_class: StorageClass::Hot,
            retention_epoch: manifest.pin_policy.retention_epoch,
        };
        let mut record = PinManifestRecord::new(
            digest,
            archive.root_cid,
            archive.chunker,
            manifest.chunk_digest_sha3_256,
            manifest.por_root,
            manifest.content_length,
            policy,
            authority.clone(),
            1,
            None,
            None,
            Metadata::default(),
        );
        assert!(!pin_record_matches_intent(
            &record, &manifest, &authority, digest
        ));
        record.record_pin_fee_payment(PinFeePayment {
            paid_by: authority.clone(),
            fee_asset_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("sora", "universal").expect("domain"),
                "xor".parse().expect("asset name"),
            ),
            treasury_account_id: authority.clone(),
            amount: Quantity::from(1_u32),
        });
        assert!(pin_record_matches_intent(
            &record, &manifest, &authority, digest
        ));
        let mut changed_manifest = manifest.clone();
        changed_manifest.content_length += 1;
        assert!(!pin_record_matches_intent(
            &record,
            &changed_manifest,
            &authority,
            digest,
        ));
        record.retire(2, None);
        assert!(!pin_record_matches_intent(
            &record, &manifest, &authority, digest
        ));
    }

    #[test]
    fn pin_completion_requires_exact_successful_network_output() {
        let (network, authority, _, manifest, key) = fixture();
        let transaction = signed_pin(network, authority, &key, &manifest, false);
        let successful = result_bearing_block(transaction.clone(), true);
        assert!(successful.validate_output_merkle_cache().is_ok());
        assert!(exact_successful_pin_transaction(&transaction, &successful).unwrap());
        let rejected = result_bearing_block(transaction.clone(), false);
        assert!(!exact_successful_pin_transaction(&transaction, &rejected).unwrap());
        let other = signed_pin(
            network,
            AccountId::new(key.public_key().clone()),
            &key,
            &manifest,
            true,
        );
        assert!(!exact_successful_pin_transaction(&other, &successful).unwrap());
    }
}
