//! Purpose-bound paid pin preparation and immutable-slot signing.
//!
//! The credential remains in this runtime owner. Public preparation constructs the canonical
//! manifest and quoted unsigned payload. The private signing leaf accepts only its closed
//! immutable slot, which persists the payload first and retains the original signed graph
//! before any subsequent fallible check. Queue admission remains the coordinator's boundary.
// TODO: Wire this signer through the immutable signed-intent outbox and finalized pin recovery,
// then qualify queue admission and provider coordination before stock publication can start.
use super::{
    MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    MusubiPublicationFinalizedArchiveRegistrationReadErrorV1,
    MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    MusubiPublicationPrivateServiceContextV1, pin_registration::validate_signed_pin_intent,
};
use iroha_config::parameters::actual::{
    MusubiPublicationPaidPinPolicy, SorafsPinPolicyConstraints,
};
use iroha_core::{
    execution_attempt::ExecutionDeferred,
    executor::quote_nexus_fee_admission_draft,
    queue::Queue,
    smartcontracts::isi::sorafs::manifest_pin_policy_constraints_from_config,
    state::{State, StateReadOnly as _, WorldReadOnly as _, WorldStateSnapshot as _},
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetId,
    isi::sorafs::RegisterPinManifest,
    musubi::MusubiArchiveCommitmentV1,
    nexus::FeeDebitSource,
    sorafs::pin_registry::{
        ManifestDigest, SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1, StorageClass,
    },
    transaction::{
        DEFAULT_TRANSACTION_TIME_TO_LIVE, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        TransactionPayload,
    },
};
use iroha_musubi_service::MusubiPublicationServiceClockV1;
use iroha_primitives::{numeric::Quantity, time::TimeSource};
use mv::storage::StorageReadOnly as _;
use sorafs_manifest::{
    DagCodecId, ManifestBuilder, ManifestV1, PinPolicy as ManifestPinPolicy, ProfileId,
    StorageClass as ManifestStorageClass,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// Redacted signer or current-state failure before any Queue admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MusubiPublicationPinSigningErrorV1 {
    /// Original local allocation admission is unfinished; retain its exact retry owner.
    Deferred(ExecutionDeferred),
    /// The source registration is ahead of this daemon's coherent finalized view.
    LocallyAhead,
    /// Runtime key does not control the configured public pin account.
    AuthorityMismatch,
    /// Finalized source archive is unavailable, invalid, or no longer current.
    Finality,
    /// The durable clock cannot be sampled or its value cannot produce a bounded retention epoch.
    Clock,
    /// Current public pin policy cannot admit the required three replicas and selected tier.
    Policy,
    /// Canonical manifest construction or archive binding failed.
    Manifest,
    /// Current pricing is invalid or this authority lacks funds for the pin and transaction fees.
    PinFunding,
    /// Current route or exact Nexus fee quote cannot admit an authority-paid pin transaction.
    TransactionFee,
    /// The exact signed pin transaction fails ordinary local admission validation.
    TransactionAdmission,
    /// The runtime credential refused or produced an invalid exact signed transaction.
    Signing,
}
impl core::fmt::Display for MusubiPublicationPinSigningErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Deferred(_) => "Musubi pin signing is waiting for local history capacity",
            Self::LocallyAhead => "Musubi pin source is ahead of local finality",
            Self::AuthorityMismatch => "Musubi pin signer authority does not match configuration",
            Self::Finality => "finalized Musubi archive is not current",
            Self::Clock => "durable Musubi pin clock is unavailable",
            Self::Policy => "current SoraFS pin policy cannot admit this publication",
            Self::Manifest => "Musubi archive cannot form a canonical pin manifest",
            Self::PinFunding => "Musubi pin funding is unavailable",
            Self::TransactionFee => "Musubi pin transaction fee admission is unavailable",
            Self::TransactionAdmission => "Musubi pin transaction admission failed",
            Self::Signing => "Musubi pin transaction signing failed",
        })
    }
}
impl std::error::Error for MusubiPublicationPinSigningErrorV1 {}
impl From<MusubiPublicationFinalizedArchiveRegistrationReadErrorV1>
    for MusubiPublicationPinSigningErrorV1
{
    fn from(error: MusubiPublicationFinalizedArchiveRegistrationReadErrorV1) -> Self {
        match error {
            MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Deferred(original) => {
                Self::Deferred(original)
            }
            MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead => {
                Self::LocallyAhead
            }
            MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Invalid => Self::Finality,
        }
    }
}

/// Runtime-only credential restricted to one canonical paid pin transaction shape.
pub struct MusubiPublicationPinTransactionSignerV1 {
    network_id: NetworkId,
    authority: AccountId,
    policy: MusubiPublicationPaidPinPolicy,
    key_pair: KeyPair,
    state: Arc<State>,
    queue: Arc<Queue>,
    finalized_reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
}
impl core::fmt::Debug for MusubiPublicationPinTransactionSignerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MusubiPublicationPinTransactionSignerV1")
            .field("network_id", &self.network_id)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}
impl MusubiPublicationPinTransactionSignerV1 {
    /// Bind a runtime-custodied software key to this daemon's exact public pin identity.
    ///
    /// This constructor accepts a key only from a deployment-owned runtime adapter; key bytes
    /// never enter `iroha_config`, a journal, an ingress request, or a signed transaction field.
    ///
    /// # Errors
    /// Rejects a key that does not control the configured canonical pin account or an invalid
    /// paid-pin horizon.
    pub fn new(
        context: &MusubiPublicationPrivateServiceContextV1,
        policy: MusubiPublicationPaidPinPolicy,
        key_pair: KeyPair,
    ) -> Result<Self, MusubiPublicationPinSigningErrorV1> {
        require_key_and_policy(&policy, &key_pair)?;
        Ok(Self {
            network_id: context.network_id(),
            authority: policy.transaction_authority.clone(),
            policy,
            key_pair,
            state: context.state(),
            queue: context.queue(),
            finalized_reader: context.finalized_archive_registration_reader(),
        })
    }

    /// Prepare the exact quoted unsigned pin for one independently authenticated archive.
    ///
    /// The native coordinator must durably retain this payload before invoking the private
    /// signing leaf. Rechecks may refuse preparation; this method never creates a signature,
    /// enters Queue, or renews an already retained payload.
    ///
    /// # Errors
    /// Preserves native source deferrals and refuses changed source, invalid funding/policy,
    /// routing, clock or a deadline outside the original finite authorization.
    pub fn prepare_finalized_archive(
        &self,
        source: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
        clock: &mut dyn MusubiPublicationServiceClockV1,
        deadline_unix_ms: u64,
    ) -> Result<(ManifestDigest, TransactionPayload), MusubiPublicationPinSigningErrorV1> {
        use MusubiPublicationPinSigningErrorV1 as Error;
        let archive = self
            .finalized_reader
            .read_current_archive(source)
            .map_err(Error::from)?;
        let now_ms = clock.current_time_ms().map_err(|_| Error::Clock)?;
        let remaining = deadline_unix_ms
            .checked_sub(now_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or(Error::Clock)?;
        let governance = self.state.governance_snapshot();
        let manifest = build_exact_pin_manifest(
            &archive.commitment,
            &self.policy,
            &governance.sorafs_pin_policy,
            now_ms,
        )?;
        self.prepare_manifest(source, &archive.commitment, manifest, now_ms, remaining)
    }

    pub(super) fn prepare_retained_pin(
        &self,
        request: &super::native_pin::slot::SlotRequest,
        source: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
        now_ms: u64,
    ) -> eyre::Result<TransactionPayload> {
        use super::native_pin::slot::{SlotKind, decode_frame};
        request.validate_pin_policy(
            self.policy.storage_class,
            self.policy.retention_horizon_secs,
        )?;
        request.authorization.ensure_live(now_ms)?;
        eyre::ensure!(
            request.kind == SlotKind::Pin
                && request.network == self.network_id
                && request.authority == self.authority,
            "native retained pin signer binding differs"
        );
        let instruction: iroha_data_model::isi::InstructionBox =
            decode_frame(&request.instruction)?;
        let pin = instruction
            .as_any()
            .downcast_ref::<RegisterPinManifest>()
            .ok_or_else(|| eyre::eyre!("native retained pin instruction differs"))?;
        let manifest = sorafs_manifest::decode_manifest_v1_canonical(&pin.manifest_payload)?;
        let archive = self.finalized_reader.read_current_archive(source)?;
        // Reuse the sole quote/funding owner while keeping the original complete manifest,
        // including its finite retention epoch. A retry cannot rebuild it from a later clock.
        let (_, payload) = self.prepare_manifest(
            source,
            &archive.commitment,
            manifest,
            now_ms,
            request.authorization.deadline_unix_ms - now_ms,
        )?;
        request
            .authorization
            .reserve_payload(&Default::default(), &payload.fee_payment, false)?;
        Ok(payload)
    }

    fn prepare_manifest(
        &self,
        source: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
        archive: &MusubiArchiveCommitmentV1,
        manifest: ManifestV1,
        now_ms: u64,
        remaining: u64,
    ) -> Result<(ManifestDigest, TransactionPayload), MusubiPublicationPinSigningErrorV1> {
        use MusubiPublicationPinSigningErrorV1 as Error;
        let governance = self.state.governance_snapshot();
        super::pin_registration::validate_pin_manifest(&manifest, archive).map_err(|error| {
            match error {
                super::MusubiPublicationFinalizedPinRegistrationReadErrorV1::Deferred(original) => {
                    Error::Deferred(original)
                }
                _ => Error::Manifest,
            }
        })?;
        sorafs_manifest::validate_manifest(
            &manifest,
            &manifest_pin_policy_constraints_from_config(&governance.sorafs_pin_policy),
        )
        .map_err(|_| Error::Policy)?;
        let digest = ManifestDigest::from_manifest(&manifest).map_err(pin_codec_refusal)?;
        let payload = manifest.encode().map_err(pin_codec_refusal)?;
        let fixed_clock = TimeSource::new_fixed(Duration::from_millis(now_ms));
        let mut draft = TransactionBuilder::new_with_time_source(
            self.network_id,
            self.authority.clone(),
            &fixed_clock,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([RegisterPinManifest::new(payload, None, None)]);
        draft.set_ttl(Duration::from_millis(remaining).min(DEFAULT_TRANSACTION_TIME_TO_LIVE));
        let route = self
            .queue
            .route_payload_plan_with_state(draft.payload(), self.state.as_ref())
            .map_err(|_| Error::TransactionFee)?;
        let iroha_core::queue::RoutingPlan::Single(route) = route else {
            return Err(Error::TransactionFee);
        };
        let view = self.state.query_view();
        let current = self
            .finalized_reader
            .read_current_archive_in_view(source, &view)
            .map_err(Error::from)?;
        if &current.commitment != archive {
            return Err(Error::Finality);
        }
        if view.world().pin_manifests().get(&digest).is_some() {
            return Err(Error::Policy);
        }
        let observation_time_ms = view
            .authenticated_query_ledger_time_ms()
            .ok_or(Error::Finality)?;
        let next_height = u64::try_from(view.block_hashes().len())
            .ok()
            .and_then(|height| height.checked_add(1))
            .ok_or(Error::Finality)?;
        let quote = quote_nexus_fee_admission_draft(
            view.world(),
            &view.nexus,
            &view.pipeline,
            &view.zk.gas,
            draft.payload(),
            observation_time_ms,
            next_height,
            Some(route.route.dataspace_id),
        )
        .map_err(|error| match error {
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                Error::Deferred(original)
            }
            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                Error::TransactionFee
            }
        })?;
        require_combined_pin_funding(
            view.world(),
            &governance.sorafs_pin_fee_asset_id,
            &self.authority,
            &manifest,
            &quote,
            observation_time_ms / 1_000,
        )?;
        drop(view);
        let payload = draft
            .with_fee_payment_intent(quote.recommended_intent)
            .into_payload()
            .map_err(|_| Error::TransactionFee)?;
        self.recheck_finalized_archive(source)?;
        Ok((digest, payload))
    }

    /// Quote only the exact closed control request already retained by the coordinator. This
    /// creates no signature and never replaces a retained payload. Controls spend fees only.
    pub(super) fn prepare_control(
        &self,
        request: &super::native_pin::slot::SlotRequest,
        now_ms: u64,
    ) -> eyre::Result<TransactionPayload> {
        use super::native_pin::slot::{SlotKind, decode_frame};
        request.validate()?;
        request.authorization.ensure_live(now_ms)?;
        eyre::ensure!(
            request.network == self.network_id
                && request.authority == self.authority
                && !matches!(request.kind, SlotKind::Pin),
            "native control signer binding differs"
        );
        let instruction: iroha_data_model::isi::InstructionBox =
            decode_frame(&request.instruction)?;
        let mut draft = TransactionBuilder::new_with_time_source(
            self.network_id,
            self.authority.clone(),
            &TimeSource::new_fixed(Duration::from_millis(now_ms)),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction]);
        draft.set_ttl(
            Duration::from_millis(request.authorization.deadline_unix_ms - now_ms)
                .min(DEFAULT_TRANSACTION_TIME_TO_LIVE),
        );
        let route = self
            .queue
            .route_payload_plan_with_state(draft.payload(), &self.state)
            .map_err(|_| eyre::eyre!("native control route is unavailable"))?;
        let iroha_core::queue::RoutingPlan::Single(route) = route else {
            eyre::bail!("native control needs one native route");
        };
        let view = self.state.query_view();
        let observed = view
            .authenticated_query_ledger_time_ms()
            .ok_or_else(|| eyre::eyre!("native control has no authenticated ledger time"))?;
        let next_height = u64::try_from(view.block_hashes().len())?
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("native control height overflow"))?;
        let quote = quote_nexus_fee_admission_draft(
            view.world(),
            &view.nexus,
            &view.pipeline,
            &view.zk.gas,
            draft.payload(),
            observed,
            next_height,
            Some(route.route.dataspace_id),
        )
        .map_err(|error| match error {
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                eyre::Report::new(original)
            }
            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                eyre::eyre!("native control fee quote is unavailable")
            }
        })?;
        eyre::ensure!(
            quote.quote.debit_source == FeeDebitSource::Account(self.authority.clone()),
            "native control fee payer differs"
        );
        for charge in &quote.quote.charges {
            let asset = quote
                .quote
                .authority_charge_assets
                .get(&charge.kind)
                .ok_or_else(|| eyre::eyre!("native control fee asset is unavailable"))?;
            eyre::ensure!(
                asset.account() == &self.authority
                    && asset.definition() == &charge.asset_definition_id,
                "native control fee source differs"
            );
            eyre::ensure!(
                view.world()
                    .assets()
                    .get(asset)
                    .is_some_and(|balance| balance.as_ref() >= &charge.max_bound)
                    || charge.max_bound.is_zero(),
                "native control fee funding is unavailable"
            );
        }
        let payload = draft
            .with_fee_payment_intent(quote.recommended_intent)
            .into_payload()?;
        request.authorization.reserve_payload(
            &Default::default(),
            &payload.fee_payment,
            matches!(request.kind, SlotKind::Check(_)),
        )?;
        Ok(payload)
    }

    /// The only production signature path consumes the immutable payload retained by its
    /// fixed-purpose slot. The slot caches the signed graph before any later fallible work.
    pub(super) fn sign_retained(
        &self,
        slot: &mut super::native_pin::slot::Slot,
        source: Option<&MusubiPublicationFinalizedArchiveRegistrationQueryV1>,
        clock: &mut dyn MusubiPublicationServiceClockV1,
        deadline: std::time::Instant,
    ) -> eyre::Result<()> {
        use super::native_pin::slot::SlotKind;
        slot.request().validate_pin_policy(
            self.policy.storage_class,
            self.policy.retention_horizon_secs,
        )?;
        eyre::ensure!(
            slot.request().network == self.network_id && slot.request().authority == self.authority,
            "native signer original identity differs"
        );
        let archive = match slot.request().kind {
            SlotKind::Pin => Some(self.finalized_reader.read_current_archive(
                source.ok_or_else(|| eyre::eyre!("native pin source original is missing"))?,
            )?),
            _ => {
                eyre::ensure!(source.is_none(), "control slot cannot select an archive");
                None
            }
        };
        if let Some(archive) = &archive {
            let payload = slot
                .payload()?
                .ok_or_else(|| eyre::eyre!("original pin payload missing"))?;
            let iroha_data_model::transaction::Executable::Instructions(values) =
                &payload.instructions
            else {
                eyre::bail!("original pin payload differs");
            };
            let pin = values[0]
                .as_any()
                .downcast_ref::<RegisterPinManifest>()
                .ok_or_else(|| eyre::eyre!("original pin instruction differs"))?;
            let manifest = sorafs_manifest::decode_manifest_v1_canonical(&pin.manifest_payload)?;
            super::pin_registration::validate_pin_manifest(&manifest, &archive.commitment)?;
        }
        slot.sign_original(&self.key_pair, clock, deadline)?;
        if let Some(archive) = archive {
            let signed = slot
                .signed()
                .ok_or_else(|| eyre::eyre!("native signature is not retained"))?;
            let iroha_data_model::transaction::Executable::Instructions(instructions) =
                signed.instructions()
            else {
                eyre::bail!("native pin instruction differs");
            };
            let pin = instructions[0]
                .as_any()
                .downcast_ref::<RegisterPinManifest>()
                .ok_or_else(|| eyre::eyre!("native pin instruction differs"))?;
            let manifest = sorafs_manifest::decode_manifest_v1_canonical(&pin.manifest_payload)?;
            let digest = ManifestDigest::from_manifest(&manifest)?;
            validate_signed_pin_intent(
                &self.network_id,
                &self.authority,
                &archive.commitment,
                signed,
                digest,
            )?;
        }
        Ok(())
    }

    pub(super) fn recheck_finalized_archive(
        &self,
        source: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    ) -> Result<(), MusubiPublicationPinSigningErrorV1> {
        self.finalized_reader
            .read_current_archive(source)
            .map(|_| ())
            .map_err(MusubiPublicationPinSigningErrorV1::from)
    }
}

#[cfg(test)]
#[path = "pin_signer/reader_tests.rs"]
mod reader_tests;

#[cfg(test)]
fn sign_quoted_pin(
    network_id: NetworkId,
    authority: &AccountId,
    archive: &MusubiArchiveCommitmentV1,
    digest: ManifestDigest,
    builder: TransactionBuilder,
    key_pair: &KeyPair,
) -> Result<SignedTransaction, MusubiPublicationPinSigningErrorV1> {
    use MusubiPublicationPinSigningErrorV1 as Error;
    let expected_payload = builder.payload().clone();
    let transaction = builder
        .try_sign(key_pair.private_key())
        .map_err(|_| Error::Signing)?;
    if transaction.payload() != &expected_payload
        || transaction.attachments().is_some()
        || transaction.multisig_signatures().is_some()
        || transaction.verify_signature().is_err()
        || validate_signed_pin_intent(&network_id, authority, archive, &transaction, digest)
            .is_err()
    {
        return Err(Error::Signing);
    }
    Ok(transaction)
}

fn require_key_and_policy(
    policy: &MusubiPublicationPaidPinPolicy,
    key_pair: &KeyPair,
) -> Result<(), MusubiPublicationPinSigningErrorV1> {
    use MusubiPublicationPinSigningErrorV1 as Error;
    if AccountId::new(key_pair.public_key().clone()) != policy.transaction_authority {
        return Err(Error::AuthorityMismatch);
    }
    if policy.retention_horizon_secs
        <= u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1)
        || policy.retention_horizon_secs
            > iroha_config::parameters::defaults::musubi_publication::MAX_PIN_RETENTION_HORIZON_SECS
    {
        return Err(Error::Policy);
    }
    Ok(())
}

fn build_exact_pin_manifest(
    archive: &MusubiArchiveCommitmentV1,
    policy: &MusubiPublicationPaidPinPolicy,
    governance: &SorafsPinPolicyConstraints,
    now_ms: u64,
) -> Result<ManifestV1, MusubiPublicationPinSigningErrorV1> {
    use MusubiPublicationPinSigningErrorV1 as Error;
    if governance.require_council_signatures {
        // A governed pending pin cannot start provider coordination without separate approval.
        return Err(Error::Policy);
    }
    if now_ms == 0 {
        return Err(Error::Clock);
    }
    let submitted_epoch = now_ms.div_ceil(1_000);
    let retention_epoch = submitted_epoch
        .checked_add(DEFAULT_TRANSACTION_TIME_TO_LIVE.as_secs())
        .and_then(|epoch| epoch.checked_add(policy.retention_horizon_secs))
        .ok_or(Error::Clock)?;
    let storage_class = match policy.storage_class {
        StorageClass::Hot => ManifestStorageClass::Hot,
        StorageClass::Warm => ManifestStorageClass::Warm,
        StorageClass::Cold => ManifestStorageClass::Cold,
    };
    let manifest = ManifestBuilder::new()
        .root_cid(archive.root_cid.as_bytes().to_vec())
        .dag_codec(DagCodecId(sorafs_manifest::MANIFEST_DAG_CODEC))
        .chunking_from_registry(ProfileId(archive.chunker.profile_id))
        .chunk_digest_sha3_256(*archive.chunk_plan_digest.as_bytes())
        .por_root(*archive.por_root.as_bytes())
        .content_length(archive.content_length)
        .car_digest(*archive.car_digest.as_bytes())
        .car_size(archive.car_size)
        .pin_policy(ManifestPinPolicy {
            min_replicas: governance.min_replicas_floor.max(3),
            storage_class,
            retention_epoch,
        })
        .build()
        .map_err(|_| Error::Manifest)?;
    if manifest.chunking.profile_id.0 != archive.chunker.profile_id
        || manifest.chunking.namespace != archive.chunker.namespace
        || manifest.chunking.name != archive.chunker.name
        || manifest.chunking.semver != archive.chunker.semver
        || manifest.chunking.multihash_code != archive.chunker.multihash_code
    {
        return Err(Error::Manifest);
    }
    let constraints = manifest_pin_policy_constraints_from_config(governance);
    sorafs_manifest::validate_manifest(&manifest, &constraints).map_err(|_| Error::Policy)?;
    Ok(manifest)
}

fn pin_codec_refusal(error: norito::Error) -> MusubiPublicationPinSigningErrorV1 {
    match super::pin_registration::codec_refusal(error) {
        super::MusubiPublicationFinalizedPinRegistrationReadErrorV1::Deferred(original) => {
            MusubiPublicationPinSigningErrorV1::Deferred(original)
        }
        _ => MusubiPublicationPinSigningErrorV1::Manifest,
    }
}

fn require_combined_pin_funding(
    world: &impl iroha_core::state::WorldReadOnly,
    pin_fee_asset: &iroha_data_model::asset::AssetDefinitionId,
    authority: &AccountId,
    manifest: &ManifestV1,
    quote: &iroha_core::executor::FeeAdmissionDraftQuote,
    submitted_epoch: u64,
) -> Result<(), MusubiPublicationPinSigningErrorV1> {
    use MusubiPublicationPinSigningErrorV1 as Error;
    let class = match manifest.pin_policy.storage_class {
        ManifestStorageClass::Hot => StorageClass::Hot,
        ManifestStorageClass::Warm => StorageClass::Warm,
        ManifestStorageClass::Cold => StorageClass::Cold,
    };
    let pin_cost = world
        .sorafs_pricing()
        .public_pin_fee(
            class,
            manifest.content_length,
            manifest.pin_policy.min_replicas,
            submitted_epoch,
            manifest.pin_policy.retention_epoch,
        )
        .map_err(|_| Error::PinFunding)?;
    let pin_asset_id = AssetId::new(pin_fee_asset.clone(), authority.clone());
    if world.accounts().get(authority).is_none() {
        return Err(Error::PinFunding);
    }
    let required_by_asset =
        quoted_authority_requirements(authority, pin_asset_id, pin_cost, quote)?;
    for (asset_id, required) in required_by_asset {
        let balance = world
            .assets()
            .get(&asset_id)
            .map_or_else(Quantity::zero, |value| value.as_ref().clone());
        if balance < required {
            return Err(Error::PinFunding);
        }
    }
    Ok(())
}

fn quoted_authority_requirements(
    authority: &AccountId,
    pin_asset_id: AssetId,
    pin_cost: Quantity,
    quote: &iroha_core::executor::FeeAdmissionDraftQuote,
) -> Result<BTreeMap<AssetId, Quantity>, MusubiPublicationPinSigningErrorV1> {
    use MusubiPublicationPinSigningErrorV1 as Error;
    if quote.quote.debit_source != FeeDebitSource::Account(authority.clone()) {
        return Err(Error::TransactionFee);
    }
    let mut required_by_asset = BTreeMap::from([(pin_asset_id, pin_cost)]);
    for charge in &quote.quote.charges {
        let selected_asset = quote
            .quote
            .authority_charge_assets
            .get(&charge.kind)
            .ok_or(Error::TransactionFee)?;
        if selected_asset.account() != authority
            || selected_asset.definition() != &charge.asset_definition_id
        {
            return Err(Error::TransactionFee);
        }
        let required = required_by_asset
            .entry(selected_asset.clone())
            .or_insert_with(Quantity::zero);
        *required = required
            .try_add(&charge.max_bound)
            .map_err(|_| Error::PinFunding)?;
    }
    Ok(required_by_asset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        asset::AssetDefinitionId,
        musubi::MusubiContentDigestV1,
        sorafs::pin_registry::{ChunkerProfileHandle, ManifestRootCid},
        transaction::FeeChargeKind,
    };
    use sorafs_manifest::PinPolicy as ManifestPinPolicy;

    fn fixture() -> (
        MusubiArchiveCommitmentV1,
        MusubiPublicationPaidPinPolicy,
        KeyPair,
    ) {
        let key_pair =
            KeyPair::try_from_seed(vec![0xC1; 32], Algorithm::Ed25519).expect("fixture key");
        let root = ManifestRootCid::from_blake3_digest([0xC2; 32]).expect("fixture CID");
        let chunker = sorafs_manifest::chunker_registry::lookup(ProfileId(1))
            .expect("registered fixture profile");
        let archive = MusubiArchiveCommitmentV1 {
            root_cid: root,
            chunker: ChunkerProfileHandle {
                profile_id: chunker.id.0,
                namespace: chunker.namespace.to_owned(),
                name: chunker.name.to_owned(),
                semver: chunker.semver.to_owned(),
                multihash_code: chunker.multihash_code,
            },
            chunk_plan_digest: MusubiContentDigestV1::new([0xC3; 32]),
            por_root: MusubiContentDigestV1::new([0xC4; 32]),
            content_length: 1_024,
            car_digest: MusubiContentDigestV1::new([0xC5; 32]),
            car_size: 2_048,
            bundle_digest: MusubiContentDigestV1::new([0xC6; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0xC7; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0xC8; 32]),
            file_count: 1,
            chunk_count: 1,
        };
        let policy = MusubiPublicationPaidPinPolicy {
            storage_class: StorageClass::Hot,
            retention_horizon_secs: 30 * 24 * 60 * 60,
            transaction_authority: AccountId::new(key_pair.public_key().clone()),
        };
        (archive, policy, key_pair)
    }

    #[test]
    fn runtime_key_binding_rejects_wrong_authority_and_unfundable_horizon() {
        let (_, mut policy, key_pair) = fixture();
        assert_eq!(require_key_and_policy(&policy, &key_pair), Ok(()));
        let other =
            KeyPair::try_from_seed(vec![0xC9; 32], Algorithm::Ed25519).expect("other fixture key");
        assert_eq!(
            require_key_and_policy(&policy, &other),
            Err(MusubiPublicationPinSigningErrorV1::AuthorityMismatch),
        );
        policy.retention_horizon_secs =
            u64::from(SORAFS_AUTO_REPLICATION_ORDER_INGEST_DEADLINE_SECS_V1);
        assert_eq!(
            require_key_and_policy(&policy, &key_pair),
            Err(MusubiPublicationPinSigningErrorV1::Policy),
        );
    }

    #[test]
    fn manifest_is_derived_from_archive_and_public_policy_with_three_replicas() {
        let (archive, policy, _) = fixture();
        let governance = SorafsPinPolicyConstraints::default();
        let manifest = build_exact_pin_manifest(&archive, &policy, &governance, 42_001)
            .expect("canonical exact pin manifest");
        assert_eq!(manifest.root_cid.as_slice(), archive.root_cid.as_bytes());
        assert_eq!(
            manifest.chunk_digest_sha3_256,
            *archive.chunk_plan_digest.as_bytes()
        );
        assert_eq!(manifest.car_digest, *archive.car_digest.as_bytes());
        assert_eq!(
            manifest.pin_policy,
            ManifestPinPolicy {
                min_replicas: 3,
                storage_class: ManifestStorageClass::Hot,
                retention_epoch: 43
                    + DEFAULT_TRANSACTION_TIME_TO_LIVE.as_secs()
                    + policy.retention_horizon_secs,
            }
        );
        assert!(manifest.alias_claims.is_empty());
        assert!(manifest.metadata.is_empty());
        assert!(manifest.governance.council_signatures.is_empty());
    }

    #[test]
    fn native_control_fee_report_preserves_typed_rejection_and_deferred_attempt() {
        use iroha_core::{
            execution_attempt::ExecutionAttemptError, executor::NexusFeeAdmissionError,
        };
        for original in [
            ExecutionAttemptError::Rejected(NexusFeeAdmissionError::ConfigInvalid(
                "exact fee configuration refusal".to_owned(),
            )),
            ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            ),
        ] {
            let expected = original.clone();
            let report = eyre::Report::new(original);
            assert_eq!(
                report.downcast_ref::<ExecutionAttemptError<NexusFeeAdmissionError>>(),
                Some(&expected)
            );
        }
    }

    #[test]
    fn canonical_manifest_resource_refusal_preserves_local_deferral() {
        let (archive, policy, _) = fixture();
        let manifest = build_exact_pin_manifest(
            &archive,
            &policy,
            &SorafsPinPolicyConstraints::default(),
            42_001,
        )
        .unwrap();
        let original = manifest.encode().unwrap();
        let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
        let result = norito::with_decode_limits_scope(zero, || {
            // The canonical decoder preserves the inherited allocation refusal through the
            // manifest wrapper and the same mapper used by signed pin readback.
            sorafs_manifest::decode_manifest_v1_canonical(&original)
                .map_err(super::super::pin_registration::manifest_codec_refusal)
        });
        assert!(matches!(
            result,
            Err(super::super::MusubiPublicationFinalizedPinRegistrationReadErrorV1::Deferred(_))
        ));
        assert_eq!(
            sorafs_manifest::decode_manifest_v1_canonical(&original).unwrap(),
            manifest
        );
    }

    #[test]
    fn manifest_preflight_rejects_mutated_archive_policy_and_inert_clock() {
        let (mut archive, mut policy, _) = fixture();
        let mut governance = SorafsPinPolicyConstraints::default();
        archive.chunker.name.push('x');
        assert_eq!(
            build_exact_pin_manifest(&archive, &policy, &governance, 42_001),
            Err(MusubiPublicationPinSigningErrorV1::Manifest),
        );
        archive.chunker.name.pop();
        governance.require_council_signatures = true;
        assert_eq!(
            build_exact_pin_manifest(&archive, &policy, &governance, 42_001),
            Err(MusubiPublicationPinSigningErrorV1::Policy),
        );
        governance.require_council_signatures = false;
        policy.storage_class = StorageClass::Warm;
        governance.allowed_storage_classes = Some([StorageClass::Hot].into());
        assert_eq!(
            build_exact_pin_manifest(&archive, &policy, &governance, 42_001),
            Err(MusubiPublicationPinSigningErrorV1::Policy),
        );
        governance.allowed_storage_classes = None;
        assert_eq!(
            build_exact_pin_manifest(&archive, &policy, &governance, 0),
            Err(MusubiPublicationPinSigningErrorV1::Clock),
        );
    }

    #[test]
    fn fee_requirements_cover_every_asset_and_combine_shared_pin_asset() {
        use iroha_core::executor::{FeeAdmissionDraftQuote, FeeAdmissionQuote, FeeChargeBound};

        let (_, policy, _) = fixture();
        let mut first = [0_u8; 16];
        first[6] = 0x40;
        first[8] = 0x80;
        first[15] = 1;
        let mut second = first;
        second[15] = 2;
        let pin_definition = AssetDefinitionId::from_uuid_bytes(first).expect("pin asset id");
        let gas_definition = AssetDefinitionId::from_uuid_bytes(second).expect("gas asset id");
        let pin_asset = AssetId::new(pin_definition.clone(), policy.transaction_authority.clone());
        let gas_asset = AssetId::new(gas_definition.clone(), policy.transaction_authority.clone());
        let mut quote = FeeAdmissionDraftQuote {
            quote: FeeAdmissionQuote {
                charges: vec![
                    FeeChargeBound {
                        kind: FeeChargeKind::Nexus,
                        asset_definition_id: pin_definition,
                        max_bound: Quantity::from(2_u32),
                    },
                    FeeChargeBound {
                        kind: FeeChargeKind::PipelineGas,
                        asset_definition_id: gas_definition,
                        max_bound: Quantity::from(3_u32),
                    },
                ],
                debit_source: FeeDebitSource::Account(policy.transaction_authority.clone()),
                program_revision: None,
                relay_leases: BTreeMap::new(),
                capacities: BTreeMap::new(),
                authority_balances: BTreeMap::new(),
                authority_charge_assets: BTreeMap::from([
                    (FeeChargeKind::Nexus, pin_asset.clone()),
                    (FeeChargeKind::PipelineGas, gas_asset.clone()),
                ]),
            },
            recommended_intent: FeePaymentIntent::authority(Vec::new(), None),
        };
        let requirements = quoted_authority_requirements(
            &policy.transaction_authority,
            pin_asset.clone(),
            Quantity::from(7_u32),
            &quote,
        )
        .expect("all exact authority fee assets are bounded");
        assert_eq!(requirements.get(&pin_asset), Some(&Quantity::from(9_u32)));
        assert_eq!(requirements.get(&gas_asset), Some(&Quantity::from(3_u32)));
        quote
            .quote
            .authority_charge_assets
            .remove(&FeeChargeKind::PipelineGas);
        assert_eq!(
            quoted_authority_requirements(
                &policy.transaction_authority,
                pin_asset,
                Quantity::from(7_u32),
                &quote,
            ),
            Err(MusubiPublicationPinSigningErrorV1::TransactionFee),
        );
    }

    #[test]
    fn signing_leaf_accepts_only_exact_sole_manifest_payload() {
        use iroha_crypto::{Hash, HashOf};
        use iroha_data_model::block::BlockHeader;

        let (archive, policy, key_pair) = fixture();
        let manifest = build_exact_pin_manifest(
            &archive,
            &policy,
            &SorafsPinPolicyConstraints::default(),
            42_001,
        )
        .expect("fixture manifest");
        let digest = ManifestDigest::from_manifest(&manifest).expect("fixture digest");
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xC9; 32]),
        ));
        let register =
            RegisterPinManifest::new(manifest.encode().expect("canonical manifest"), None, None);
        let builder = TransactionBuilder::new_with_time_source(
            network,
            policy.transaction_authority.clone(),
            &TimeSource::new_fixed(Duration::from_millis(42_001)),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([register.clone()]);
        let signed = sign_quoted_pin(
            network,
            &policy.transaction_authority,
            &archive,
            digest,
            builder,
            &key_pair,
        )
        .expect("purpose-bound signer accepts the exact pin");
        assert!(signed.verify_signature().is_ok());
        let duplicate = TransactionBuilder::new(
            network,
            policy.transaction_authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([register.clone(), register]);
        assert!(matches!(
            sign_quoted_pin(
                network,
                &policy.transaction_authority,
                &archive,
                digest,
                duplicate,
                &key_pair,
            ),
            Err(MusubiPublicationPinSigningErrorV1::Signing),
        ));
        let wrong_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xCA; 32])),
        );
        let wrong_domain = TransactionBuilder::new(
            wrong_network,
            policy.transaction_authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([RegisterPinManifest::new(
            manifest.encode().expect("canonical manifest"),
            None,
            None,
        )]);
        assert!(matches!(
            sign_quoted_pin(
                network,
                &policy.transaction_authority,
                &archive,
                digest,
                wrong_domain,
                &key_pair,
            ),
            Err(MusubiPublicationPinSigningErrorV1::Signing),
        ));
    }
}
