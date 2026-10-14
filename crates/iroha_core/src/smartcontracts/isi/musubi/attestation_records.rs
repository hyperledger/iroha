//! Borrowed, complete provider-attestation evidence for one immutable World borrow.
//!
//! References and result handles have fixed stack capacity after location bounds
//! are validated. This helper does not clone records, signatures, controllers,
//! or encoded preimages into its local containers. Its constructor returns evidence
//! after the whole exact set and every controller signature have passed.
//! Semantic failures retain their original static model reason. Instruction callers
//! construct an owned invariant error only at their completed-result boundary.
// TODO: signature backend caches/workspaces and backend/codec errors still need
// their actual allocation owner before this helper can support funded State
// projection capture. Fixed local containers do not fund cryptographic work.

use super::*;
use iroha_data_model::sorafs::capacity::ProviderId;
use iroha_model_base::error::ParseError;

/// Records admitted by the complete-set checks, in canonical provider order.
/// The record references retain the same World borrow used for every check.
#[derive(Clone, Copy, Debug)]
pub struct LocationProviderAttestations<'world> {
    records:
        [Option<&'world MusubiProviderBundleAttestationRecordV1>; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
    len: usize,
}

impl<'world> LocationProviderAttestations<'world> {
    /// Number of initialized, verified references in the bounded result.
    pub(super) fn len(&self) -> usize {
        self.len
    }

    /// Borrow the initialized records, preserving the validated provider order.
    pub(super) fn iter(
        &self,
    ) -> impl Iterator<Item = &'world MusubiProviderBundleAttestationRecordV1> + '_ {
        self.records[..self.len].iter().filter_map(|record| *record)
    }
}

/// Verify the exact complete set before exposing any borrowed records to callers.
pub fn load_location_provider_attestations<'world>(
    archive: &MusubiArchiveRecordV1,
    location: &MusubiArchiveLocationV1,
    world: &'world impl MusubiSourceReadOnly,
) -> Result<LocationProviderAttestations<'world>, ParseError> {
    try_load_location_provider_attestations(archive, location, world)
        .map_err(ReadFailure::into_predicate)
}

/// Run the same predicate while preserving an original physical read refusal.
pub(crate) fn try_load_location_provider_attestations<'world, W: MusubiRead>(
    archive: &MusubiArchiveRecordV1,
    location: &MusubiArchiveLocationV1,
    world: &'world W,
) -> Result<LocationProviderAttestations<'world>, ReadFailure<W::Error, ParseError>> {
    let mut records = LocationProviderAttestations {
        records: [None; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
        len: location.providers.len(),
    };
    ProviderAttestationValidation::new().advance(archive, location, world, |index, record| {
        records.records[index] = Some(record);
    })?;
    Ok(records)
}

/// Original immutable-location verification cursor; verified signatures never repeat on retry.
pub(crate) struct ProviderAttestationValidation {
    queries: [LookupCursor; 1],
    initialized: bool,
    next: usize,
    references: [MusubiProviderBundleAttestationRefV1; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
    verification_lock_digest: Option<iroha_data_model::musubi::MusubiVerificationLockDigestV1>,
    complete: bool,
    rejected: Option<ParseError>,
}
impl ProviderAttestationValidation {
    /// Begin without reading or allocating. The enclosing original owner pins the source.
    pub(crate) fn new() -> Self {
        Self {
            initialized: false,
            queries: [LookupCursor::new(); 1],
            next: 0,
            references: [MusubiProviderBundleAttestationRefV1 {
                provider_id: ProviderId::new([0; 32]),
                digest: MusubiProviderBundleAttestationDigestV1::new([0; 32]),
            }; MUSUBI_MAX_LOCATION_PROVIDERS_V1],
            verification_lock_digest: None,
            complete: false,
            rejected: None,
        }
    }
    /// Complete the same predicate, preserving each original source refusal.
    /// The private source owner must use one unchanged archive/location on every retry.
    pub(crate) fn advance<'world, W: MusubiRead>(
        &mut self,
        archive: &MusubiArchiveRecordV1,
        location: &MusubiArchiveLocationV1,
        world: &'world W,
        mut verified: impl FnMut(usize, &'world MusubiProviderBundleAttestationRecordV1),
    ) -> Result<(), ReadFailure<W::Error, ParseError>> {
        if let Some(original) = self.rejected {
            return Err(original.into());
        }
        if self.complete {
            return Ok(());
        }
        let result = self.advance_inner(archive, location, world, &mut verified);
        if let Err(ReadFailure::Predicate(original)) = &result {
            self.rejected = Some(*original);
        }
        result
    }
    fn advance_inner<'world, W: MusubiRead>(
        &mut self,
        archive: &MusubiArchiveRecordV1,
        location: &MusubiArchiveLocationV1,
        world: &'world W,
        verified: &mut impl FnMut(usize, &'world MusubiProviderBundleAttestationRecordV1),
    ) -> Result<(), ReadFailure<W::Error, ParseError>> {
        if !self.initialized {
            archive.validate()?;
            location.validate()?;
            if location.archive_id != archive.archive_id {
                return Err(ParseError::new(
                    "Musubi archive location does not match its archive directory",
                )
                .into());
            }
            self.initialized = true;
        }
        let receipt = &archive.staging_receipt.payload.binding;
        while self.next < location.providers.len() {
            let index = self.next;
            let provider = &location.providers[index];
            let key = MusubiProviderBundleAttestationKeyV1 {
                archive_id: archive.archive_id,
                replication_order: location.replication_order,
                provider_id: *provider,
            };
            let record = world
                .musubi_provider_bundle_attestations_get_retained(&key, &mut self.queries[0])
                .map_err(ReadFailure::Source)?
                .ok_or_else(|| {
                    ParseError::new(
                        "Musubi archive location provider attestation record was not found",
                    )
                })?;
            record.validate()?;
            if record.key != key
                || record.registered_at_height < archive.registered_at_height
                || record.registered_at_height >= location.finalized_height
            {
                return Err(ParseError::new(
                "Musubi archive location provider attestation record is not a finalized predecessor",
            ).into());
            }
            let binding = &record.attestation.payload.binding;
            if binding.network_id != receipt.network_id
                || binding.provider_id != *provider
                || binding.replication_order != location.replication_order
                || binding.archive_id != archive.archive_id
                || binding.bundle_digest != archive.commitment.bundle_digest
                || binding.descriptor_digest != archive.commitment.descriptor_digest
                || binding.semantic_release_manifest_digest
                    != receipt.semantic_release_manifest_digest
                || binding.source_tree_digest != archive.commitment.source_tree_digest
            {
                return Err(ParseError::new(
                "Musubi archive location attestation does not match its immutable archive commitments",
            ).into());
            }
            if self
                .verification_lock_digest
                .replace(binding.verification_lock_digest)
                .is_some_and(|digest| digest != binding.verification_lock_digest)
            {
                return Err(ParseError::new(
                    "Musubi archive location attestations disagree on the verification lock",
                )
                .into());
            }
            record.attestation.verify(binding)?;
            self.references[index] = record.attestation.reference();
            verified(index, record);
            self.next += 1;
            self.queries[0].reset();
        }
        let set_digest = musubi_provider_bundle_attestation_set_digest_v1(
            archive.archive_id,
            location.replication_order,
            &self.references[..location.providers.len()],
        )?;
        if set_digest != location.provider_attestation_set_digest {
            return Err(ParseError::new(
                "Musubi archive location provider attestation set digest is inconsistent",
            )
            .into());
        }
        self.complete = true;
        Ok(())
    }
}
