//! Concrete native paid-pin, isolated source staging and replication coordination.
//!
//! The original operation lives only in the portable pin journal. Provider workers perform
//! actual ingestion/completion; the publisher separately obtains and registers signed inventory.

mod staging;
#[cfg(test)]
mod tests;

use super::{
    MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    MusubiPublicationFinalizedSeedReadCapabilityV1, MusubiPublicationPrivateServiceContextV1,
    MusubiPublicationPrivateServiceFactoryErrorV1, MusubiPublicationPrivateStorageBuilderV1,
    NativeMusubiFinalizedPinV1, NativeMusubiPinCoordinatorV1, NativeMusubiPinProgressV1,
    NativePinAuthorizationV1,
};
use eyre::{Result, ensure};
use iroha_config::parameters::actual::MusubiPublicationPaidPinPolicy;
use iroha_core::{
    query::native_musubi_storage::{
        NativeMusubiStorageObservationV1, with_native_musubi_storage_v1,
    },
    state::{State, StateReadOnly as _},
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    account::AccountId,
    asset::AssetDefinitionId,
    musubi::{MUSUBI_MAX_CAR_BYTES_V1, MusubiArchiveLocationIdV1},
    transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent},
};
use iroha_musubi_service::{
    MusubiPublicationServiceBackendErrorV1 as BackendError, MusubiPublicationServiceClockV1,
    MusubiStorageCoordinationBackendV1, MusubiStorageCoordinationRequestV1,
    MusubiStorageCoordinationResponseV1, MusubiStorageLocationDispositionV1,
    VerifiedStorageCoordinationRequestV1,
};
use iroha_primitives::numeric::Quantity;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

const MAX_ROW_BYTES: usize = 1024 * 1024;
const LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    16 * 1024 * 1024,
    16 * 1024 * 1024,
    16 * 1024 * 1024,
    8 * MUSUBI_MAX_CAR_BYTES_V1 as usize,
    64,
);

/// Configured operator ceilings; the public-pin principal remains separately native-priced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeMusubiStorageLimitsV1 {
    /// Maximum original operation lifetime, further capped by the verified caller expiry.
    pub authorization_window_ms: u64,
    /// Maximum fresh signed native Check rounds for one operation.
    pub max_check_rounds: u16,
    /// Exact configured Nexus fee asset.
    pub fee_asset: AssetDefinitionId,
    /// Maximum charge for each individual retained native transaction.
    pub per_transaction_fee: Quantity,
    /// Aggregate ceiling for every retained control and pin payload, including failed work.
    pub total_fees: Quantity,
}
impl NativeMusubiStorageLimitsV1 {
    fn authorization(
        &self,
        observed: u64,
        caller_expires: u64,
    ) -> Result<NativePinAuthorizationV1> {
        ensure!(
            observed > 0 && (1..=3_600_000).contains(&self.authorization_window_ms),
            "native storage requires finite original time"
        );
        let deadline_unix_ms = observed
            .checked_add(self.authorization_window_ms)
            .ok_or_else(|| eyre::eyre!("native storage authorization overflow"))?
            .min(caller_expires);
        let selected = NativePinAuthorizationV1 {
            deadline_unix_ms,
            max_check_rounds: self.max_check_rounds,
            per_transaction: FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    self.fee_asset.clone(),
                    self.per_transaction_fee.clone(),
                )],
                None,
            ),
            max_total_fees: BTreeMap::from([(self.fee_asset.clone(), self.total_fees.clone())]),
        };
        selected.ensure_live(observed)?;
        Ok(selected)
    }
    fn validate(&self) -> Result<()> {
        self.authorization(1, u64::MAX - 1).map(|_| ())
    }
    fn matches(&self, original: &NativePinAuthorizationV1) -> Result<()> {
        let expected = self.authorization(1, u64::MAX - 1)?;
        ensure!(
            original.max_check_rounds == expected.max_check_rounds
                && original.per_transaction == expected.per_transaction
                && original.max_total_fees == expected.max_total_fees,
            "native storage configured fee/round selection changed"
        );
        Ok(())
    }
}

/// Closed native builder. The root/session must already have been provisioned atomically.
/// Constructing this value never initializes missing history or starts a listener.
pub struct NativeMusubiStorageBuilderV1 {
    root: PathBuf,
    session: [u8; 32],
    key: KeyPair,
    limits: NativeMusubiStorageLimitsV1,
}
impl NativeMusubiStorageBuilderV1 {
    /// Retain the exact original private session and runtime-only paid pin credential.
    /// # Errors
    /// Refuses inert sessions and invalid finite fee/round limits.
    pub fn new(
        root: PathBuf,
        session: [u8; 32],
        key: KeyPair,
        limits: NativeMusubiStorageLimitsV1,
    ) -> Result<Self> {
        ensure!(session != [0; 32], "native storage session is zero");
        limits.validate()?;
        Ok(Self {
            root,
            session,
            key,
            limits,
        })
    }
}
impl MusubiPublicationPrivateStorageBuilderV1 for NativeMusubiStorageBuilderV1 {
    fn build(
        self: Box<Self>,
        context: &MusubiPublicationPrivateServiceContextV1,
        finalized_reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
        finalized_seed: MusubiPublicationFinalizedSeedReadCapabilityV1,
        paid_pin: MusubiPublicationPaidPinPolicy,
        clock: Box<dyn MusubiPublicationServiceClockV1>,
    ) -> Result<
        Box<dyn MusubiStorageCoordinationBackendV1>,
        MusubiPublicationPrivateServiceFactoryErrorV1,
    > {
        if context.sorafs_node().config().provider_id() != Some(finalized_seed.provider_id()) {
            return Err(MusubiPublicationPrivateServiceFactoryErrorV1::Unqualified);
        }
        let storage = context
            .sorafs_node()
            .storage()
            .ok_or(MusubiPublicationPrivateServiceFactoryErrorV1::Unqualified)?;
        let authority = paid_pin.transaction_authority.clone();
        let pin = NativeMusubiPinCoordinatorV1::open(
            context,
            &self.root,
            self.session,
            paid_pin,
            self.key,
        )
        .map_err(|_| MusubiPublicationPrivateServiceFactoryErrorV1::Unavailable)?;
        Ok(Box::new(NativeMusubiStorageBackendV1 {
            state: context.state(),
            pin,
            authority,
            reader: finalized_reader,
            seed: finalized_seed,
            storage,
            clock: Mutex::new(clock),
            limits: self.limits,
        }))
    }
}

/// Runtime-owned coordinator; no constructor accepts caller-created native finality.
struct NativeMusubiStorageBackendV1 {
    state: Arc<State>,
    pin: NativeMusubiPinCoordinatorV1,
    authority: AccountId,
    reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    seed: MusubiPublicationFinalizedSeedReadCapabilityV1,
    storage: Arc<sorafs_node::store::StorageBackend>,
    clock: Mutex<Box<dyn MusubiPublicationServiceClockV1>>,
    limits: NativeMusubiStorageLimitsV1,
}
struct ClockSample<'a>(&'a Mutex<Box<dyn MusubiPublicationServiceClockV1>>);
impl MusubiPublicationServiceClockV1 for ClockSample<'_> {
    fn current_time_ms(&mut self) -> Result<u64, BackendError> {
        self.0
            .lock()
            .map_err(|_| BackendError::Retryable)?
            .current_time_ms()
    }
}
impl NativeMusubiStorageBackendV1 {
    fn observe(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
        pin: &NativeMusubiFinalizedPinV1,
        now: u64,
    ) -> Result<Option<MusubiStorageCoordinationResponseV1>> {
        let view = self.state.view();
        with_native_musubi_storage_v1(
            &view,
            &self.authority,
            request.commitment.archive_id(),
            pin.query().manifest_digest,
            pin.query().finalized_height,
            self.seed.provider_id(),
            now / 1_000,
            |facts| {
                if facts.complete {
                    self.response(request, facts).map(Some)
                } else {
                    Ok(None)
                }
            },
        )?
    }
    fn response(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
        facts: NativeMusubiStorageObservationV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1> {
        ensure!(facts.complete, "native replication has not completed");
        let original = &request.finalized_registration.registration;
        ensure!(
            facts.archive.archive_id == original.archive_id
                && facts.archive.commitment == original.commitment
                && facts.archive.staging_receipt == original.staging_receipt
                && facts.archive.registered_by == original.registered_by
                && facts.archive.registered_at_height == original.registered_at_height,
            "native archive differs from the original request"
        );
        let (location_id, renew_after_epoch, expires_at_epoch, disposition) =
            if let Some(location) = facts.location {
                (
                    location.location_id,
                    location.renew_after_epoch,
                    location.expires_at_epoch,
                    MusubiStorageLocationDispositionV1::Registered(bounded_copy(location)?),
                )
            } else {
                let expires = facts.pin.policy.retention_epoch;
                let horizon = expires
                    .checked_sub(facts.pin.submitted_epoch)
                    .filter(|value| *value > 1)
                    .ok_or_else(|| eyre::eyre!("native pin lifetime is invalid"))?;
                let mut providers = Vec::new();
                norito::core::reserve_decode_allocation(std::mem::size_of_val(
                    facts.completed_providers,
                ))?;
                providers.try_reserve_exact(facts.completed_providers.len())?;
                providers.extend_from_slice(facts.completed_providers);
                (
                    location_id(request, facts.pin.digest.as_bytes())?,
                    facts.pin.submitted_epoch + horizon / 2,
                    expires,
                    MusubiStorageLocationDispositionV1::NeedsRegistration {
                        completed_providers: providers,
                        expected_location_revision: facts.archive.location_revision,
                    },
                )
            };
        let response = MusubiStorageCoordinationResponseV1 {
            version: 1,
            request_digest: request.canonical_request_digest()?,
            archive: bounded_copy(facts.archive)?,
            location_id,
            pin_manifest: facts.pin.digest,
            replication_order: facts.order.order_id,
            renew_after_epoch,
            expires_at_epoch,
            disposition,
        };
        response.validate_for(request)?;
        Ok(response)
    }
    fn selected_source(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
        digest: [u8; 32],
    ) -> Result<(
        [u8; 32],
        MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    )> {
        request.validate()?;
        ensure!(
            request.network_id == *self.state.network_id_ref()
                && request.staging_receipt.payload.binding.seed_provider == self.seed.provider_id(),
            "native storage request belongs to another original network or seed owner"
        );
        let id = operation_id(request)?;
        let source = source_query(request)?;
        self.reader.read_current_archive(&source)?;
        if let Some(original) = self.pin.original_operation(id)? {
            ensure!(
                original.context_digest == digest && original.source == source,
                "native storage request changed its retained original"
            );
            self.limits.matches(&original.authorization)?;
        }
        Ok((id, source))
    }
    fn coordinate(
        &mut self,
        verified: &VerifiedStorageCoordinationRequestV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1> {
        let request = verified.request();
        ensure!(
            Instant::now() < verified.deadline(),
            "native storage caller deadline expired"
        );
        let (id, source) = self.selected_source(request, verified.canonical_request_digest())?;
        let authorization = match self.pin.original_operation(id)? {
            Some(original) => {
                // Expiry forbids further effects, not independently observed completion. This
                // path retains the original request/authorization and never stages or dispatches.
                if let NativeMusubiPinProgressV1::Finalized(pin) = self.pin.observe_operation(id)? {
                    if let Some(response) = read_current_for_call(
                        verified.authorization_expires_at_ms(),
                        verified.deadline(),
                        &mut ClockSample(&self.clock),
                        |now| self.observe(request, &pin, now),
                    )? {
                        return Ok(response);
                    }
                }
                original.authorization
            }
            None => {
                let selected = self.limits.authorization(
                    verified.observed_at_unix_ms(),
                    verified.authorization_expires_at_ms(),
                )?;
                selected
                    .check_effect_boundary(&mut ClockSample(&self.clock), verified.deadline())?;
                self.pin.prepare_operation(
                    id,
                    verified.canonical_request_digest(),
                    &source,
                    selected.clone(),
                )?;
                selected
            }
        };
        // Never renew a retained UTC ceiling from this call's newer signed authorization.
        authorization.check_effect_boundary(&mut ClockSample(&self.clock), verified.deadline())?;
        let progress = self
            .pin
            .advance(id, &mut ClockSample(&self.clock), verified.deadline())?;
        let NativeMusubiPinProgressV1::Finalized(pin) = progress else {
            eyre::bail!("original native pin work remains pending");
        };
        self.stage(request, &pin, &authorization, verified.deadline())?;
        read_current_for_call(
            verified.authorization_expires_at_ms(),
            verified.deadline(),
            &mut ClockSample(&self.clock),
            |now| self.observe(request, &pin, now),
        )?
        .ok_or_else(|| eyre::eyre!("native replication has not completed"))
    }
}
impl MusubiStorageCoordinationBackendV1 for NativeMusubiStorageBackendV1 {
    fn verify_current_registration(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), BackendError> {
        norito::with_decode_limits_scope(LIMITS, || -> Result<()> {
            let (id, _) = self.selected_source(request, request.canonical_request_digest()?)?;
            ensure!(
                self.pin.original_operation(id)?.is_some(),
                "cached native storage original is missing"
            );
            let NativeMusubiPinProgressV1::Finalized(pin) = self.pin.observe_operation(id)? else {
                eyre::bail!("cached native storage pin is not finalized");
            };
            let now = ClockSample(&self.clock).current_time_ms()?;
            ensure!(
                self.observe(request, &pin, now)?.is_some(),
                "cached native replication is incomplete"
            );
            Ok(())
        })
        .map_err(|_| BackendError::Retryable)
    }
    fn coordinate_storage(
        &mut self,
        request: &VerifiedStorageCoordinationRequestV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1, BackendError> {
        norito::with_decode_limits_scope(LIMITS, || self.coordinate(request))
            .map_err(|_| BackendError::Retryable)
    }
}

/// A fresh signed call bounds read-only native observation independently from expired original
/// effect authorization. The observation supplies all native facts; this helper supplies only time.
fn read_current_for_call<T>(
    expires: u64,
    deadline: Instant,
    clock: &mut dyn MusubiPublicationServiceClockV1,
    read: impl FnOnce(u64) -> Result<T>,
) -> Result<T> {
    ensure!(
        Instant::now() < deadline,
        "native storage caller deadline expired"
    );
    let now = clock.current_time_ms()?;
    ensure!(
        now > 0 && now < expires && Instant::now() < deadline,
        "native storage caller authorization expired"
    );
    let observed = read(now)?;
    let after = clock.current_time_ms()?;
    ensure!(
        after >= now && after < expires && Instant::now() < deadline,
        "native storage caller authorization expired during observation"
    );
    Ok(observed)
}

fn operation_id(request: &MusubiStorageCoordinationRequestV1) -> Result<[u8; 32]> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    request.validate()?;
    let mut hash = Sha256::new();
    hash.update(b"iroha/native-musubi-storage-operation/v1\0");
    hash.update(request.network_id.as_bytes());
    let length = norito::canonical_frame_len(&request.publisher)?;
    ensure!(length <= 8192, "native storage publisher is oversized");
    let account = norito::core::to_bytes_bounded(&request.publisher, length)
        .map_err(|error| match error {
            norito::core::BoundedEncodeError::Serialization(error)
                if error.decode_resource_error().is_some() => eyre::Report::from(error),
            error => eyre::Report::from(error),
        })?;
    hash.update((account.len() as u64).to_le_bytes());
    hash.update(account);
    hash.update(request.operation_id);
    hash.update([request.generation]);
    Ok(hash.finalize().into())
}
fn location_id(
    request: &MusubiStorageCoordinationRequestV1,
    manifest: &[u8; 32],
) -> Result<MusubiArchiveLocationIdV1> {
    let mut hash = Sha256::new();
    hash.update(b"iroha/native-musubi-storage-location/v1\0");
    hash.update(operation_id(request)?);
    hash.update(manifest);
    Ok(MusubiArchiveLocationIdV1::new(hash.finalize().into()))
}
fn source_query(
    request: &MusubiStorageCoordinationRequestV1,
) -> Result<MusubiPublicationFinalizedArchiveRegistrationQueryV1> {
    let evidence = &request.finalized_registration;
    Ok(MusubiPublicationFinalizedArchiveRegistrationQueryV1 {
        version: evidence.version,
        network_id: evidence.network_id,
        transaction_hash: evidence.transaction_hash,
        snapshot: evidence.snapshot,
        registration: bounded_copy(&evidence.registration)?,
        expected_policy_revision: request.expected_policy_revision,
    })
}
fn bounded_copy<T>(value: &T) -> Result<T>
where
    T: norito::core::NoritoSerialize + for<'a> norito::core::NoritoDeserialize<'a>,
{
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::canonical_frame_len(value)?;
    ensure!(
        length <= MAX_ROW_BYTES,
        "native storage row exceeds its bound"
    );
    let bytes = norito::core::to_bytes_bounded(value, length)
        .map_err(|error| match error {
            norito::core::BoundedEncodeError::Serialization(error)
                if error.decode_resource_error().is_some() => eyre::Report::from(error),
            error => eyre::Report::from(error),
        })?;
    Ok(norito::decode_canonical(&bytes)?)
}
