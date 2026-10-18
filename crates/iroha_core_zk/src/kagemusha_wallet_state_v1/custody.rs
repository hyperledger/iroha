//! Concrete adapter and deterministic G1 assembly for the existing Advance provider.

use crate::kagemusha_wallet_archive_bytes_v1::PrivateArchiveBytes;
use std::sync::{Arc, Mutex, MutexGuard};

use iroha_data_model::kagemusha::*;

mod deletion;
pub use deletion::{CustodyDeletionProgressV1, CustodyDeletionReviewV1, ReviewedCustodyDeletionV1};

use super::{AdvanceOutcome, AdvanceRequest, Lookup, ProviderError, SlotStatus};
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletFsV1, KagemushaWalletPlatformV1, KagemushaWalletProviderV1,
    KagemushaWalletSlotIdV1, KagemushaWalletTransitionOwnerV1,
};

fn invalid<T>(result: Result<T, KagemushaWalletValidationErrorV1>) -> Result<T, ProviderError> {
    result.map_err(|_| ProviderError::Invalid {
        field: "state_owner",
    })
}

/// The only authority for operation completion. Production callers use [`AdvanceHandle`].
///
/// Implementors must uphold the Advance contract: no released result without a durable
/// selected marker and verified completion, immutable retained bytes, and explicit uncertain
/// outcomes. This injection point supports custody fault tests, not an alternate monetary
/// engine or software replacement for the platform payment key.
pub trait Custody {
    /// Read the exact manifest selected by the source marker, never a filesystem guess.
    ///
    /// # Errors
    /// Missing selected data or unavailable custody is an error, never `None`.
    fn archive_checkpoint(&mut self) -> Result<Option<([u8; 32], Vec<u8>)>, ProviderError>;
    /// Bind durable index roots in a new metadata generation without changing the head.
    ///
    /// # Errors
    /// Stale roots, storage failures and uncertain publication; no error reverses a head.
    fn publish_archive_checkpoint(
        &mut self,
        expected: [u8; 32],
        bytes: &[u8],
    ) -> Result<[u8; 32], ProviderError>;

    /// Reconcile the current source-bound marker, including protected-data checks.
    ///
    /// # Errors
    /// Provider reconciliation, protected storage or key errors.
    fn status(&mut self) -> Result<SlotStatus, ProviderError>;
    /// Look up a retained operation without signing. The provider binds the current head's
    /// completion to its Released marker. Historical frames also need the coordinator's
    /// source-selected StepEntry or frozen-capsule verification before exposing their output.
    ///
    /// # Errors
    /// Provider errors, never converted to absence.
    fn lookup(
        &mut self,
        operation_id: &[u8; 32],
    ) -> Result<Lookup<KagemushaWalletCompletionRecordV1>, ProviderError>;
    /// Remove exactly one older capsule's redundant copies after durable owner collection intent.
    /// # Errors
    /// Current-head attempts, uncertain storage or an unavailable protected-data bracket.
    fn collect_capsule(&mut self, generation: u128, capsule: [u8; 32])
    -> Result<(), ProviderError>;
    /// Publish a permanent source tombstone before pruning an older completion.
    /// # Errors
    /// Unknown/current operations, conflicting tombstones or uncertain storage.
    fn prune_completion(
        &mut self,
        operation: [u8; 32],
        kind: u8,
    ) -> Result<crate::kagemusha_wallet_advance_v1::KagemushaWalletTombstoneV1, ProviderError>;
    /// Select and complete one transition under the provider's durable commit protocol.
    ///
    /// # Errors
    /// Same errors and unknown-write semantics as the native Advance provider.
    fn advance(
        &mut self,
        owner: &TransitionOwner,
        request: &AdvanceRequest<KagemushaWalletRecoveryCapsuleV1>,
    ) -> Result<AdvanceOutcome<KagemushaWalletCompletionRecordV1>, ProviderError>;
    /// Free custody storage and memory available to the app now (design §5.3).
    ///
    /// # Errors
    /// Locked protected storage or unreadable free space; never a shortfall.
    fn runtime_resources(
        &mut self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1, ProviderError>;
}

/// Owns the exclusive native provider handle and binds calls to one enrolled slot.
pub struct AdvanceHandle<F: KagemushaWalletFsV1, P> {
    provider: Arc<Mutex<KagemushaWalletProviderV1<F, P>>>,
    slot: KagemushaWalletSlotIdV1,
    deletion_owner: Arc<()>,
    deletion: deletion::DeletionState,
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> AdvanceHandle<F, P> {
    /// Move the exclusive provider into the shared coordinator's slot adapter.
    #[must_use]
    pub fn new(provider: KagemushaWalletProviderV1<F, P>, slot: KagemushaWalletSlotIdV1) -> Self {
        Self {
            provider: Arc::new(Mutex::new(provider)),
            slot,
            deletion_owner: Arc::new(()),
            deletion: deletion::DeletionState::Open,
        }
    }
    pub(super) fn try_into_provider(self) -> Result<KagemushaWalletProviderV1<F, P>, Self> {
        let Self {
            provider,
            slot,
            deletion_owner,
            deletion,
        } = self;
        take_exclusive(provider).map_err(|provider| Self {
            provider,
            slot,
            deletion_owner,
            deletion,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, KagemushaWalletProviderV1<F, P>>, ProviderError> {
        self.require_custody_operations()?;
        let mut provider = self.provider.lock().map_err(|_| ProviderError::Invalid {
            field: "provider handle poisoned",
        })?;
        // Every custody call ends the current archive phase; the next archive access reconciles.
        provider.end_archive_phase();
        Ok(provider)
    }
    pub(crate) fn sign_setup(
        &self,
        source: [u8; 32],
        key: &KagemushaDevicePublicKeyV1,
        domain: KagemushaWalletSigningDomainV1,
        body: &[u8],
    ) -> Result<KagemushaDeviceSignatureV1, ProviderError> {
        self.lock()?
            .sign_setup(&self.slot, source, key, domain, body)
    }

    pub(crate) fn sign_activation(
        &self,
        source: [u8; 32],
        key: &KagemushaDevicePublicKeyV1,
        body: &KagemushaWalletLedgerControlBodyV1,
    ) -> Result<KagemushaDeviceSignatureV1, ProviderError> {
        self.lock()?.sign_activation(&self.slot, source, key, body)
    }

    pub(crate) fn sign_close_loads(
        &self,
        source: [u8; 32],
        key: &KagemushaDevicePublicKeyV1,
        body: &KagemushaWalletLedgerControlBodyV1,
    ) -> Result<KagemushaDeviceSignatureV1, ProviderError> {
        self.lock()?.sign_close_loads(&self.slot, source, key, body)
    }

    /// Share only native observations with the concrete proof/preparation owner.
    pub(crate) fn observations(&self) -> NativeObservationsV1<F, P> {
        NativeObservationsV1 {
            provider: Arc::clone(&self.provider),
        }
    }

    /// Create the matching archive capability. Both adapters share one provider and its
    /// exclusive custody lifetime. Archive calls between two custody calls share one archive
    /// phase: the first reconciles the slot, and every call that touches storage is followed
    /// by a protected-storage probe.
    #[must_use]
    pub fn archive(&self, scheme_id: [u8; 32], wallet_id: [u8; 32]) -> ProviderArchive<F, P> {
        ProviderArchive {
            provider: Arc::clone(&self.provider),
            slot: self.slot,
            scheme_id,
            wallet_id,
        }
    }
}

// Once Arc::try_unwrap succeeds no other thread can poison the mutex. Check poison
// after that ownership transfer, retaining the exact poisoned cell until explicit close.
fn take_exclusive<T>(shared: Arc<Mutex<T>>) -> Result<T, Arc<Mutex<T>>> {
    match Arc::try_unwrap(shared) {
        Ok(cell) if cell.is_poisoned() => Err(Arc::new(cell)),
        Ok(cell) => Ok(cell.into_inner().unwrap_or_else(|error| error.into_inner())),
        Err(shared) => Err(shared),
    }
}

#[cfg(test)]
mod exclusive_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Held(Arc<AtomicUsize>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn extra_owner_retains_exact_custody_until_unique() {
        let drops = Arc::new(AtomicUsize::new(0));
        let original = Arc::new(Mutex::new(Held(Arc::clone(&drops))));
        let other = Arc::clone(&original);
        let retained = take_exclusive(original).err().expect("shared");
        assert!(Arc::ptr_eq(&retained, &other));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(other);
        let value = take_exclusive(retained).ok().expect("exclusive");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(value);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poisoned_unique_custody_is_retained_without_unpoisoning() {
        let drops = Arc::new(AtomicUsize::new(0));
        let original = Arc::new(Mutex::new(Held(Arc::clone(&drops))));
        let other = Arc::clone(&original);
        assert!(
            std::thread::spawn(move || {
                let _held = other.lock().expect("unpoisoned");
                panic!("inject owner failure");
            })
            .join()
            .is_err()
        );
        let retained = take_exclusive(original).err().expect("poisoned");
        assert!(retained.is_poisoned());
        let retained = take_exclusive(retained).err().expect("still poisoned");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(retained);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

/// Private clock capability sharing the actual exclusive provider lifetime.
/// It grants no payment-key, storage or Advance access.
pub(crate) struct NativeObservationsV1<F: KagemushaWalletFsV1, P> {
    provider: Arc<Mutex<KagemushaWalletProviderV1<F, P>>>,
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> NativeObservationsV1<F, P> {
    pub(crate) fn time(&self) -> Result<KagemushaWalletMonotonicReadingV1, ProviderError> {
        self.provider
            .lock()
            .map_err(|_| ProviderError::Invalid {
                field: "provider handle poisoned",
            })?
            .monotonic_reading()
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> Custody for AdvanceHandle<F, P> {
    fn archive_checkpoint(&mut self) -> Result<Option<([u8; 32], Vec<u8>)>, ProviderError> {
        self.lock()?.archive_checkpoint(&self.slot)
    }
    fn publish_archive_checkpoint(
        &mut self,
        expected: [u8; 32],
        bytes: &[u8],
    ) -> Result<[u8; 32], ProviderError> {
        self.lock()?
            .publish_archive_checkpoint(&self.slot, expected, bytes)
    }

    fn status(&mut self) -> Result<SlotStatus, ProviderError> {
        self.lock()?.status(&self.slot)
    }
    fn runtime_resources(
        &mut self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1, ProviderError>
    {
        self.lock()?.runtime_resources()
    }
    fn lookup(
        &mut self,
        operation_id: &[u8; 32],
    ) -> Result<Lookup<KagemushaWalletCompletionRecordV1>, ProviderError> {
        self.lock()?.lookup(&self.slot, operation_id)
    }
    fn collect_capsule(
        &mut self,
        generation: u128,
        capsule: [u8; 32],
    ) -> Result<(), ProviderError> {
        self.lock()?
            .collect_capsule(&self.slot, generation, &capsule)
    }
    fn prune_completion(
        &mut self,
        operation: [u8; 32],
        kind: u8,
    ) -> Result<crate::kagemusha_wallet_advance_v1::KagemushaWalletTombstoneV1, ProviderError> {
        self.lock()?.prune_completion(&self.slot, &operation, kind)
    }
    fn advance(
        &mut self,
        owner: &TransitionOwner,
        request: &AdvanceRequest<KagemushaWalletRecoveryCapsuleV1>,
    ) -> Result<AdvanceOutcome<KagemushaWalletCompletionRecordV1>, ProviderError> {
        self.lock()?.advance(&self.slot, owner, request)
    }
}

/// Pure G1 receipt/output assembler. It neither proves transitions nor selects a head.
pub struct TransitionOwner {
    credential: KagemushaWalletCredentialV1,
}

impl TransitionOwner {
    /// Hold the exact credential already authenticated by the native transition verifier.
    #[must_use]
    pub fn new(credential: &KagemushaWalletCredentialV1) -> Self {
        Self {
            credential: *credential,
        }
    }

    fn require(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
    ) -> Result<(), ProviderError> {
        invalid(capsule.body().validate())?;
        invalid(
            capsule
                .body()
                .statement
                .validate_for_credential(&self.credential),
        )?;
        if capsule.custody_digest() != *capsule_digest
            || capsule.body().wallet_id != self.credential.body.wallet_id
        {
            return Err(ProviderError::Invalid {
                field: "state_owner.binding",
            });
        }
        if let KagemushaWalletEffectV1::Send {
            request: expected, ..
        } = capsule.body().statement.effect
        {
            let request = self.request(capsule)?;
            if request.request_digest() != expected {
                return Err(ProviderError::Invalid {
                    field: "state_owner.request_digest",
                });
            }
        }
        Ok(())
    }

    fn request(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
    ) -> Result<KagemushaWalletRequestV1, ProviderError> {
        let mut requests = capsule
            .body()
            .retained_inputs
            .iter()
            .filter(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request);
        let bytes = &requests
            .next()
            .ok_or(ProviderError::Invalid {
                field: "state_owner.request",
            })?
            .bytes;
        if requests.next().is_some() || bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(ProviderError::Invalid {
                field: "state_owner.request",
            });
        }
        let request: KagemushaWalletRequestV1 = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|_| ProviderError::Invalid {
            field: "state_owner.request",
        })?;
        invalid(request.validate())?;
        let payer = &self.credential.body;
        if request.body.payer_wallet_id != payer.wallet_id
            || request.body.payer_account_digest != payer.account_digest
            || request.body.scheme_id != payer.scheme_id
            || request.body.asset_digest != payer.asset_digest
            || request.receiver_credential.body.payment_key == payer.payment_key
        {
            return Err(ProviderError::Invalid {
                field: "state_owner.request_payer",
            });
        }
        Ok(request)
    }
}

impl
    KagemushaWalletTransitionOwnerV1<
        KagemushaWalletRecoveryCapsuleV1,
        KagemushaWalletCompletionRecordV1,
    > for TransitionOwner
{
    fn receipt_body(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require(capsule, capsule_digest)?;
        let signer = invalid(KagemushaWalletReceiptSignerV1::from_credential(
            &self.credential,
        ))?;
        let body = invalid(KagemushaWalletReceiptBodyV1::derive(
            &signer,
            &capsule.body().statement,
            &invalid(capsule.proof_digest())?,
            capsule.receipt_commitment(),
            capsule.body().payment_digest,
        ))?;
        Ok(body.transcript())
    }

    fn require_completion(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        record: &KagemushaWalletCompletionRecordV1,
    ) -> Result<(), ProviderError> {
        invalid(record.verify(&self.credential, capsule)).map(|_| ())
    }

    fn assemble(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
        signature: &KagemushaDeviceSignatureV1,
    ) -> Result<KagemushaWalletCompletionRecordV1, ProviderError> {
        self.require(capsule, capsule_digest)?;
        let receipt = KagemushaWalletReceiptV1 {
            version: 1,
            operation_id: capsule.body().operation_id,
            capsule_commitment: capsule.receipt_commitment(),
            payment_digest: capsule.body().payment_digest,
            signature: *signature,
        };
        let package = KagemushaWalletPackageV1::new(
            capsule.body().statement.clone(),
            capsule.body().predecessor_lineage.clone(),
            capsule.body().step_proof.clone(),
            receipt,
        );
        invalid(package.verify(&self.credential))?;
        let output = if capsule.body().kind == KagemushaWalletOperationKindV1::Send {
            let request = self.request(capsule)?;
            invalid(KagemushaWalletPaymentV1::assemble(
                &request,
                &self.credential,
                package,
            ))?
            .to_canonical_bytes()
            .map_err(|_| ProviderError::Invalid {
                field: "state_owner.payment",
            })?
        } else {
            norito::encode_canonical(&package).map_err(|_| ProviderError::Invalid {
                field: "state_owner.package",
            })?
        };
        let record = invalid(KagemushaWalletCompletionRecordV1::new(
            capsule, receipt, output,
        ))?;
        invalid(record.verify(&self.credential, capsule))?;
        Ok(record)
    }
}

/// State-owner archive under the same provider lock, directory capability and storage probes
/// as monetary custody. Create through [`AdvanceHandle::archive`].
///
/// Accesses run inside the provider's current archive phase (reconciled once, ended by every
/// custody call). Content-addressed objects read through [`super::ObjectStore`] accept the first
/// redundant copy that passes every check and are kept, authenticated, for the rest of the
/// phase; every other key reads and compares both copies.
pub struct ProviderArchive<F: KagemushaWalletFsV1, P> {
    provider: Arc<Mutex<KagemushaWalletProviderV1<F, P>>>,
    slot: KagemushaWalletSlotIdV1,
    scheme_id: [u8; 32],
    wallet_id: [u8; 32],
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> ProviderArchive<F, P> {
    fn lock(&self) -> Result<MutexGuard<'_, KagemushaWalletProviderV1<F, P>>, super::Error> {
        self.provider
            .lock()
            .map_err(|_| super::Error::Invalid("provider handle poisoned"))
    }

    // Provider record key of one archive key.
    fn identity(key: super::ArchiveKey) -> Result<[u8; 32], super::Error> {
        use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1 as digest;
        Ok(digest("wallet-archive-key", &super::archive::encode(&key)?))
    }

    // Phase identity of one authenticated object of this incarnation.
    fn object_key(&self, identity: [u8; 32]) -> [[u8; 32]; 3] {
        [self.scheme_id, self.wallet_id, identity]
    }

    fn record_limit(max_bytes: usize) -> Result<usize, super::Error> {
        Ok(max_bytes
            .checked_add(super::archive::METADATA_BOUND)
            .ok_or(ProviderError::Invalid {
                field: "archive size",
            })?)
    }

    // Authenticate one record's canonical envelope: incarnation, key, bound and content digest.
    fn authenticate(
        &self,
        key: super::ArchiveKey,
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<PrivateArchiveBytes, super::Error> {
        use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1 as digest;
        let envelope: super::archive::Envelope = super::archive::decode(bytes)?;
        if envelope.version != 1
            || envelope.scheme_id != self.scheme_id
            || envelope.wallet_id != self.wallet_id
            || envelope.key != key
            || envelope.content.len() > max_bytes
            || envelope.content_digest != digest("wallet-archive-content", &envelope.content)
        {
            return Err(super::Error::WitnessLost("provider archive authentication"));
        }
        Ok(envelope.content)
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> super::ArchiveStore
    for ProviderArchive<F, P>
{
    fn binding(&self) -> ([u8; 32], [u8; 32]) {
        (self.scheme_id, self.wallet_id)
    }
    fn get(
        &mut self,
        key: super::ArchiveKey,
        max_bytes: usize,
    ) -> Result<Option<PrivateArchiveBytes>, super::Error> {
        let identity = Self::identity(key)?;
        let limit = Self::record_limit(max_bytes)?;
        let mut provider = self.lock()?;
        let Some(bytes) = provider
            .with_archive_phase(&self.slot, |archive| archive.read_record(&identity, limit))?
        else {
            return Ok(None);
        };
        self.authenticate(key, &bytes, max_bytes)
            .inspect_err(|_| provider.end_archive_phase())
            .map(Some)
    }
    fn get_object(
        &mut self,
        digest: [u8; 32],
        max_bytes: usize,
    ) -> Result<Option<PrivateArchiveBytes>, super::Error> {
        let key = super::ArchiveKey::Object(digest);
        let identity = Self::identity(key)?;
        let object = self.object_key(identity);
        let limit = Self::record_limit(max_bytes)?;
        let mut provider = self.lock()?;
        // Kept content is the authenticated content of this exact key; any other bound is
        // answered from disk with today's exact error.
        if let Some(content) = provider.archive_phase_object(&self.slot, &object, max_bytes)? {
            return Ok(Some(content));
        }
        let Some(bytes) = provider.with_archive_phase(&self.slot, |archive| {
            archive.read_record_first(&identity, limit)
        })?
        else {
            return Ok(None);
        };
        // The first copy whose prefix verifies must pass every check; a failure is never
        // retried with the redundant copy.
        let content = self
            .authenticate(key, &bytes, max_bytes)
            .and_then(|content| {
                if crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
                    &content,
                ) == digest
                {
                    Ok(content)
                } else {
                    Err(super::Error::WitnessLost("index object digest"))
                }
            })
            .inspect_err(|_| provider.end_archive_phase())?;
        provider.keep_archive_phase_object(&self.slot, object, &content)?;
        Ok(Some(content))
    }
    fn remove(&mut self, key: super::ArchiveKey) -> Result<(), super::Error> {
        let identity = Self::identity(key)?;
        let object = self.object_key(identity);
        let mut provider = self.lock()?;
        // Forgotten by the phase (and, in `remove_record`, by the write memo) before any unlink.
        provider.forget_archive_phase_object(&object);
        provider.with_archive_phase(&self.slot, |archive| archive.remove_record(&identity))?;
        Ok(())
    }
    fn put(&mut self, key: super::ArchiveKey, bytes: &[u8]) -> Result<(), super::Error> {
        use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1 as digest;
        let identity = Self::identity(key)?;
        let envelope = super::archive::Envelope {
            version: 1,
            scheme_id: self.scheme_id,
            wallet_id: self.wallet_id,
            key,
            content_digest: digest("wallet-archive-content", bytes),
            content: PrivateArchiveBytes::copy_from(bytes)?,
        };
        let encoded = PrivateArchiveBytes::encode(&envelope)
            .map_err(|_| super::Error::Invalid("private archive encoding"))?;
        drop(envelope);
        let mut provider = self.lock()?;
        provider.with_archive_phase(&self.slot, |archive| {
            archive.write_record(&identity, &encoded)
        })?;
        // Both copies are durable: an object's exact content stays readable for the phase.
        if let super::ArchiveKey::Object(object) = key
            && crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(bytes)
                == object
        {
            provider.keep_archive_phase_object(&self.slot, self.object_key(identity), bytes)?;
        }
        Ok(())
    }
}
