//! Fixed request binding and validated, recoverable preparation publication.

use super::super::super::object_workspace::{
    DraftWorkspace, MaterializedObjects, ObjectBatch, ReadOnlyWorkspace, WorkspaceLimits,
};
use super::*;
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1 as object_digest;
use crate::kagemusha_wallet_archive_bytes_v1::PrivateArchiveBytes;

// One derivation: at most two IMT mutations, each performing at most 68 Patricia
// updates that each emit at most 258 bounded nodes. Six original roles are a
// conservative bound over every supported refresh variant. Fresh intake and a review's
// speculation each stage only their one planning derivation.
pub(in crate::kagemusha_wallet_state_v1) const DRAFT_OBJECTS: usize = 35_094;
pub(in crate::kagemusha_wallet_state_v1) const DRAFT_BYTES: usize = 56_144_656;
pub(in crate::kagemusha_wallet_state_v1) const BATCH_BYTES: usize =
    DRAFT_BYTES + DRAFT_OBJECTS * 512 + REQUEST_MAX_BYTES + PLAN_BOUND + 4096;

fn limits() -> WorkspaceLimits {
    WorkspaceLimits {
        max_bytes: DRAFT_BYTES,
        max_objects: DRAFT_OBJECTS,
    }
}

fn binding(
    scheme: &[u8; 32],
    wallet: &[u8; 32],
    request: &NativeIntentV1,
    bytes: &[u8],
) -> [u8; 32] {
    let mut input = [0; 128];
    input[..32].copy_from_slice(scheme);
    input[32..64].copy_from_slice(wallet);
    input[64..96].copy_from_slice(&request.request_id());
    input[96..].copy_from_slice(&object_digest(bytes));
    digest("wallet-intake-binding", &input)
}

impl Entry {
    pub(super) fn bound(
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        request: &NativeIntentV1,
        bytes: &[u8],
    ) -> Self {
        Self {
            binding: binding(scheme, wallet, request, bytes),
            kind: request.kind(),
            request: None,
            plan: None,
            capsule: None,
            capsule_commitment: None,
            operation: None,
        }
    }

    pub(super) fn retained_request(&self) -> Result<[u8; 32], Error> {
        self.request.ok_or(Error::Pending)
    }

    pub(super) fn require_request(
        &self,
        archive: &mut impl ObjectStore,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        request: &NativeIntentV1,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if self.kind != request.kind() || self.binding != binding(scheme, wallet, request, bytes) {
            return Err(Error::OperationConflict);
        }
        if let Some(original) = self.request {
            let retained =
                zeroize::Zeroizing::new(archive.read_object(&original, REQUEST_MAX_BYTES)?);
            if retained.as_slice() != bytes {
                return Err(Error::OperationConflict);
            }
        }
        Ok(())
    }
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ValidatedIntakeBatchV1")]
struct IntakeBatch {
    version: u16,
    request_id: [u8; 32],
    binding: [u8; 32],
    original: PrivateArchiveBytes,
    plan: Plan,
    objects: BatchObjects,
}

// Norito v1 sequence counts are fixed-width little-endian u64. Inspect the count
// before delegating any sequence planning or Vec allocation to the canonical codec.
struct BatchObjects(Vec<([u8; 32], PrivateArchiveBytes)>);

impl norito::NoritoSchema for BatchObjects {
    fn nominal_name() -> String {
        "iroha.kagemusha.intake_objects.v1".into()
    }
}
impl norito::SerializePayload for BatchObjects {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::SerializePayload::serialize(&self.0, writer)
    }
}
impl<'de> norito::core::DecodeFromSlice<'de> for BatchObjects {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let count = u64::from_le_bytes(
            bytes
                .get(..8)
                .ok_or(norito::Error::LengthMismatch)?
                .try_into()
                .map_err(|_| norito::Error::LengthMismatch)?,
        );
        if count > DRAFT_OBJECTS as u64 {
            return Err(norito::Error::SequenceLengthExceeded {
                length: count,
                limit: DRAFT_OBJECTS as u64,
            });
        }
        <Vec<([u8; 32], PrivateArchiveBytes)> as norito::core::DecodeFromSlice>::decode_from_slice(
            bytes,
        )
        .map(|(objects, used)| (Self(objects), used))
    }
}
impl<'de> norito::DeserializePayload<'de> for BatchObjects {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("bounded intake objects")
    }
    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes)
            .map(|(objects, _)| objects)
    }
}

fn decode_batch(bytes: &[u8]) -> Result<IntakeBatch, Error> {
    if bytes.len() > BATCH_BYTES {
        return Err(Error::WitnessLost("intake batch frame bound"));
    }
    let limits = norito::DecodeLimits::new(
        BATCH_BYTES,
        BATCH_BYTES,
        2 * BATCH_BYTES,
        2 * BATCH_BYTES,
        norito::core::MAX_VALUE_NESTING_DEPTH,
    );
    norito::core::classify_decode_attempt(|| norito::decode_canonical_with_limits(bytes, limits))
        .map_err(|error| {
            super::super::super::decode_attempt_error(
                error,
                Error::WitnessLost("canonical intake batch"),
            )
        })
}

fn encode_batch(batch: &IntakeBatch) -> Result<PrivateArchiveBytes, Error> {
    let length =
        norito::canonical_frame_len(batch).map_err(|_| Error::Invalid("intake batch encoding"))?;
    if length > BATCH_BYTES {
        return Err(Error::NotEnoughMemory);
    }
    PrivateArchiveBytes::encode(batch).map_err(|_| Error::Invalid("intake batch encoding"))
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    fn read_intake_batch(
        &mut self,
        request_id: [u8; 32],
        entry: &Entry,
    ) -> Result<Option<IntakeBatch>, Error> {
        let _observation = iroha_plonk::work_metrics::WorkTimer::start(
            iroha_plonk::work_metrics::WorkPhase::SourceRestore,
        );
        self.require_intake_memory()?;
        let Some(bytes) = self
            .archive
            .get(ArchiveKey::PreparationDraft(request_id), BATCH_BYTES)?
        else {
            return Ok(None);
        };
        // ArchiveStore returns a clearing PrivateArchiveBytes owner, including on decode error.
        let batch = decode_batch(&bytes)?;
        if batch.version != 1
            || batch.request_id != request_id
            || batch.binding != entry.binding
            || batch.original.len() > REQUEST_MAX_BYTES
            || batch.objects.0.len() > DRAFT_OBJECTS
        {
            return Err(Error::WitnessLost("intake batch binding"));
        }
        let (scheme, _) = self.proofs.ledger_scope()?;
        let request = NativeIntentV1::decode(&batch.original, &scheme)?;
        if request.request_id() != request_id
            || request.kind() != entry.kind
            || binding(&self.scheme_id, &self.wallet_id, &request, &batch.original) != entry.binding
        {
            return Err(Error::WitnessLost("intake batch original binding"));
        }
        batch
            .plan
            .require(&self.scheme_id, &self.wallet_id, &request, &batch.original)?;
        if batch.plan.request_object != object_digest(&batch.original) {
            return Err(Error::WitnessLost("intake batch request object"));
        }
        Ok(Some(batch))
    }

    /// Model the real pre-publication state where the batch is the sole original owner.
    #[cfg(test)]
    pub(in crate::kagemusha_wallet_state_v1) fn retain_intake_batch_only_test_original(
        &mut self,
        request_id: [u8; 32],
    ) -> Result<(), Error> {
        let (mut selected, mut manifest) = self.manifest()?;
        let mut entry = self
            .preparation_entry(&manifest, &request_id)?
            .ok_or(Error::WitnessLost("test intake entry"))?;
        let batch = self
            .read_intake_batch(request_id, &entry)?
            .ok_or(Error::WitnessLost("test intake batch"))?;
        if entry.plan.is_some()
            || entry.capsule.is_some()
            || entry.request != Some(batch.plan.request_object)
        {
            return Err(Error::WitnessLost("test intake publication boundary"));
        }
        entry.request = None;
        self.publish_preparation(&mut selected, &mut manifest, request_id, &entry)
    }

    pub(super) fn pending_intake_original(
        &mut self,
        request_id: [u8; 32],
        entry: &Entry,
    ) -> Result<Option<PrivateArchiveBytes>, Error> {
        Ok(self
            .read_intake_batch(request_id, entry)?
            .map(|batch| batch.original))
    }
}

impl<C: Custody, A: ArchiveStore, N: NativePreparation> Coordinator<C, A, N> {
    #[expect(
        clippy::too_many_arguments,
        reason = "one exclusively selected intake transaction"
    )]
    pub(super) fn prepare_intake_plan(
        &mut self,
        request: &NativeIntentV1,
        original: &[u8],
        source: &PreparationSourceV1<'_>,
        snapshot: &SourceCustodyV1,
        map_state: &KagemushaWalletStateV1,
        entry: &mut Entry,
        selected: &mut [u8; 32],
        manifest: &mut manifest::Manifest,
        speculative: Option<&N::Speculative>,
    ) -> Result<Option<(Plan, N::Prepared)>, Error> {
        let key = ArchiveKey::PreparationDraft(request.request_id());
        let source_digest = source.released().frozen.capsule.custody_digest();
        let mut planned = None;
        let recovered = match self.read_intake_batch(request.request_id(), entry)? {
            // A stale Archive batch can be replaced only before a plan/capsule was selected.
            // Its immutable key cannot be overwritten. First retain its exact original under
            // the authenticated Entry, then retire the old copies before staging a new batch.
            Some(batch)
                if batch.plan.source != source_digest
                    && request.kind() == KagemushaWalletOperationKindV1::ArchiveSent =>
            {
                entry.require_binding()?;
                if entry.plan.is_some() || entry.capsule.is_some() || entry.operation.is_some() {
                    return Err(Error::WitnessLost("stale Archive batch already planned"));
                }
                if batch.original.as_slice() != original {
                    return Err(Error::WitnessLost("retained intake original changed"));
                }
                let request_object = self.archive.write_object(original, REQUEST_MAX_BYTES)?;
                if request_object != batch.plan.request_object {
                    return Err(Error::WitnessLost("stale Archive original digest"));
                }
                entry.request = Some(request_object);
                self.publish_preparation(selected, manifest, request.request_id(), entry)?;
                // Publication ends the grouped-write phase. Verify the retained original
                // through the fresh phase before deleting its formerly sole batch copy.
                let retained = zeroize::Zeroizing::new(
                    self.archive
                        .read_object(&request_object, REQUEST_MAX_BYTES)?,
                );
                if retained.as_slice() != original {
                    return Err(Error::WitnessLost("stale Archive retained original"));
                }
                self.archive.remove(key)?;
                None
            }
            recovered => recovered,
        };
        let batch = if let Some(batch) = recovered {
            batch
        } else {
            self.require_intake_capacity()?;
            let mut workspace = DraftWorkspace::new(&mut self.archive, limits());
            let (native, draft) = {
                let mut custody = PreparationCustodyV1::new(
                    &mut workspace,
                    snapshot,
                    map_state,
                    request.kind(),
                    request.refresh(),
                    manifest.issued_requests,
                    manifest.direct_anchors,
                    manifest.finality_epochs,
                    manifest.blacklist.clone(),
                )?;
                let (native, prepared) = match speculative {
                    // A review's speculation supplies its own choices for this exact request.
                    Some(speculative) => {
                        self.proofs
                            .plan_speculated(request, source, &mut custody, speculative)?
                    }
                    None => self
                        .proofs
                        .plan_preparation(request, source, &mut custody)?,
                };
                // Planned in this call: this one derivation is reused through proving.
                planned = Some(prepared);
                let native = PrivateArchiveBytes::from_guarded(zeroize::Zeroizing::new(native));
                (native, custody.snapshot())
            };
            let plan = Plan {
                version: 1,
                scheme: self.scheme_id,
                wallet: self.wallet_id,
                request_id: request.request_id(),
                kind: request.kind(),
                request: digest("wallet-preparation-request", original),
                source: source_digest,
                native,
                request_object: object_digest(original),
                draft,
            };
            plan.require(&self.scheme_id, &self.wallet_id, request, original)?;
            IntakeBatch {
                version: 1,
                request_id: request.request_id(),
                binding: entry.binding,
                original: PrivateArchiveBytes::copy_from(original)?,
                plan,
                objects: BatchObjects(workspace.into_batch().into_owned()),
            }
        };
        if batch.original.as_slice() != original {
            return Err(Error::WitnessLost("retained intake original changed"));
        }
        if batch.plan.source != source_digest {
            return Ok(None);
        }
        // A present one-copy batch is not a durability acknowledgment: re-put its exact
        // canonical original before materializing any objects, including after restart.
        let encoded = encode_batch(&batch)?;
        let IntakeBatch { plan, objects, .. } = batch;
        let objects = ObjectBatch::from_owned(objects.0, limits())?;
        let prepared = if let Some(prepared) = planned {
            prepared
        } else {
            // A recovered batch came from storage: replay it before any object materializes.
            let mut readonly = ReadOnlyWorkspace::with_batch(&mut self.archive, &objects);
            let mut custody = PreparationCustodyV1::new(
                &mut readonly,
                snapshot,
                map_state,
                request.kind(),
                request.refresh(),
                manifest.issued_requests,
                manifest.direct_anchors,
                manifest.finality_epochs,
                manifest.blacklist.clone(),
            )?;
            let prepared =
                self.proofs
                    .validate_preparation(request, source, &mut custody, &plan.native)?;
            if archive::encode(&custody.snapshot())? != archive::encode(&plan.draft)? {
                return Err(Error::WitnessLost("retained intake draft changed"));
            }
            prepared
        };
        self.archive.put(key, &encoded)?;
        // Recovery is durably acknowledged; object promotion needs only the decoded batch.
        drop(encoded);
        let materialized = objects.materialize(&mut self.archive)?;
        let plan = self.promote_intake_plan(
            materialized,
            request,
            original,
            plan,
            entry,
            selected,
            manifest,
        )?;
        // The promote publication opened a new archive phase. Read every materialized
        // original back from storage before dispatch may remove the recovery batch.
        objects.read_back(&mut self.archive)?;
        Ok(Some((plan, prepared)))
    }

    // Only a complete durable materialization can reach the plan publication boundary.
    #[expect(
        clippy::too_many_arguments,
        reason = "one exclusively selected intake transaction"
    )]
    fn promote_intake_plan(
        &mut self,
        _materialized: MaterializedObjects,
        request: &NativeIntentV1,
        original: &[u8],
        plan: Plan,
        entry: &mut Entry,
        selected: &mut [u8; 32],
        manifest: &mut manifest::Manifest,
    ) -> Result<Plan, Error> {
        let request_object = self.archive.write_object(original, REQUEST_MAX_BYTES)?;
        if request_object != plan.request_object {
            return Err(Error::WitnessLost("intake request publication digest"));
        }
        if norito::canonical_frame_len(&plan).map_err(|_| Error::Invalid("intake plan encoding"))?
            > PLAN_BOUND
        {
            return Err(Error::Invalid("intake plan bound"));
        }
        let plan_bytes = PrivateArchiveBytes::encode(&plan)
            .map_err(|_| Error::Invalid("intake plan encoding"))?;
        let plan_object = self.archive.write_object(&plan_bytes, PLAN_BOUND)?;
        entry.request = Some(request_object);
        entry.plan = Some(plan_object);
        self.publish_preparation(selected, manifest, request.request_id(), entry)?;
        // Common dispatch performs idempotent staging cleanup only after this acknowledgment.
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::core::DecodeFromSlice;

    #[test]
    fn batch_object_count_is_rejected_before_collection_decode() {
        for count in [DRAFT_OBJECTS as u64 + 1, u64::MAX] {
            assert!(
                matches!(BatchObjects::decode_from_slice(&count.to_le_bytes()),
                Err(norito::Error::SequenceLengthExceeded { length, limit })
                if length == count && limit == DRAFT_OBJECTS as u64)
            );
        }
        assert!(BatchObjects::decode_from_slice(&[]).is_err());
        assert_eq!(
            BatchObjects::decode_from_slice(&0u64.to_le_bytes())
                .unwrap()
                .0
                .0
                .len(),
            0
        );
    }

    #[test]
    fn binding_includes_request_identity_even_for_equal_actions() {
        let first = NativeIntentV1::user(OperationRequestV1 {
            request_id: [1; 32],
            action: OperationActionV1::Unload {
                amount: 1,
                charge: None,
            },
        });
        let second = NativeIntentV1::user(OperationRequestV1 {
            request_id: [2; 32],
            action: OperationActionV1::Unload {
                amount: 1,
                charge: None,
            },
        });
        assert_ne!(
            binding(&[3; 32], &[4; 32], &first, b"same bytes"),
            binding(&[3; 32], &[4; 32], &second, b"same bytes")
        );
    }
}
