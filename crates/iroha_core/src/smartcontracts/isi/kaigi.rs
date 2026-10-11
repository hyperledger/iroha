//! Host-side execution of Kaigi instruction family.
use crate::{
    execution_attempt::{ExecutionAttemptError, norito_decode_attempt_error},
    smartcontracts::limits,
    state::{StateReadOnly, StateTransaction, World, WorldReadOnly},
};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1;
use iroha_data_model::{
    HasMetadata, Identifiable,
    account::rekey::{AccountAlias, AccountRekeyTransitionProvenance},
    events::{
        data::prelude::{
            KaigiRelayHealthSummary, KaigiRelayManifestSummary, KaigiRelayRegistrationSummary,
            KaigiRelayUnregistrationSummary, KaigiRosterSummary, KaigiStatusSummary,
            KaigiUsageSummary,
        },
        prelude::{DomainEvent, MetadataChanged},
    },
    isi::{
        error::{InstructionExecutionError as Error, InvalidParameterError},
        kaigi::{
            CreateKaigi, EndKaigi, JoinKaigi, LeaveKaigi, RecordKaigiUsage, RegisterKaigiRelay,
            ReportKaigiRelayHealth, SetKaigiRelayManifest, UnregisterKaigiRelay,
        },
    },
    kaigi::{
        KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1, KAIGI_MAX_PARTICIPANTS_V1,
        KAIGI_MAX_USAGE_COMMITMENTS_V1, KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1,
        KAIGI_RECORD_MAX_JSON_BYTES_V1, KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1,
        KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1, KAIGI_RELAY_MANIFEST_MAX_HOPS_V1,
        KAIGI_RELAY_MANIFEST_MIN_HOPS_V1, KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1, KaigiId,
        KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiPrivacyMode, KaigiRecord,
        KaigiRelayAllowlist, KaigiRelayFeedback, KaigiRelayManifest, KaigiRelayRegistration,
        KaigiStatus, kaigi_metadata_key, kaigi_relay_allowlist_key, kaigi_relay_feedback_key,
        kaigi_relay_metadata_key,
    },
    prelude::{AccountId, Domain, Json},
    query::error::FindError,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use kaigi_zk::authorization_v1::KaigiAuthorizationActionV1;
use mv::storage::StorageReadOnly;
use privacy::PrivacyArtifacts;
use privacy::authorization_v1::{
    context_from_ledger_v1, ensure_action_capacity_v1, original_participant_v1,
};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
};
mod privacy;
mod relay_lifecycle_guard_v1;
#[cfg(test)]
mod relay_restore_key_tests;
#[cfg(test)]
mod relay_typed_deferral_tests;
mod storage_reservation_v1;
#[cfg(test)]
mod typed_deferral_tests;

type KaigiAccountDependencyLocator = (u8, DomainId, Name);

// Relay-state kinds must sort before active-call references so relay-home checks remain bounded
// even when one account participates in many active calls.
const KAIGI_DEPENDENCY_RELAY_REGISTRATION: u8 = 0;
const KAIGI_DEPENDENCY_RELAY_FEEDBACK: u8 = 1;
const KAIGI_DEPENDENCY_ACTIVE_CALL: u8 = 2;
const KAIGI_RELAY_HEALTH_NOTES_MAX_CHARS_V1: usize = 512;

/// Signature-authenticated account authorizing a Kaigi state transition.
#[derive(Clone, Copy, Debug)]
enum KaigiAuthorization<'a> {
    SignedAccount(&'a AccountId),
}
impl<'a> KaigiAuthorization<'a> {
    fn signed_account(self) -> &'a AccountId {
        match self {
            Self::SignedAccount(authority) => authority,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessGrant {
    Default,
    PrivacyAuthorized,
    NoRecordUpdate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordUpdateEffect {
    None,
    Roster,
    Usage,
    RelayManifest,
    Status,
}
use super::super::Execute;
trait ExecuteKaigiAuthorized {
    fn execute_authorized(
        self,
        authorization: KaigiAuthorization<'_>,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error>;
}
impl ExecuteKaigiAuthorized for CreateKaigi {
    fn execute_authorized(
        self,
        authorization: KaigiAuthorization<'_>,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let CreateKaigi {
            call: template,
            commitment,
            nullifier,
            roster_root,
            proof,
        } = self;
        if let Some(limit) = template.max_participants {
            if limit == 0 {
                return Err(Error::InvalidParameter(
                    InvalidParameterError::SmartContract(
                        "Kaigi max_participants must be greater than zero when provided".into(),
                    ),
                ));
            }
            if usize::try_from(limit).unwrap_or(usize::MAX) > KAIGI_MAX_PARTICIPANTS_V1 {
                return Err(Error::InvalidParameter(
                    InvalidParameterError::SmartContract(format!(
                        "Kaigi max_participants must not exceed {KAIGI_MAX_PARTICIPANTS_V1}"
                    )),
                ));
            }
        }
        let authority = authorization.signed_account();
        if authority != template.host() {
            return Err(unauthorized("only the host account may create a Kaigi"));
        }
        state_transaction.world.account(authority)?;
        if resolve_active_kaigi_account(state_transaction, authority)?.as_ref() != Some(authority) {
            return Err(Error::InvariantViolation(
                "Kaigi host must be the unique registered terminal account-id rekey successor"
                    .into(),
            ));
        }
        if let Some(billing_account) = template.billing_account.as_ref() {
            if authority != billing_account {
                return Err(unauthorized(
                    "Kaigi billing account must be the signed host until delegated billing authorization is supported",
                ));
            }
            state_transaction.world.account(billing_account)?;
        }
        let key = metadata_key(template.id())?;
        let domain_id = template.id().domain_id.clone();
        if state_transaction
            .world
            .domain(&domain_id)?
            .metadata()
            .contains(&key)
        {
            return Err(Error::InvariantViolation("Kaigi already exists".into()));
        }
        match template.privacy_mode {
            KaigiPrivacyMode::Transparent => {
                privacy::ensure_transparent_payload(&PrivacyArtifacts {
                    commitment: commitment.as_ref(),
                    nullifier: nullifier.as_ref(),
                    roster_root: roster_root.as_ref(),
                    proof: proof.as_deref(),
                })?;
            }
            KaigiPrivacyMode::ZkRosterV1 => {
                let expected_root = KaigiRecord::compute_roster_root(&[]);
                ensure_action_capacity_v1(0, 0, KaigiAuthorizationActionV1::HostCreate)?;
                let context = context_from_ledger_v1(
                    *state_transaction.network_id(),
                    template.id(),
                    template.host(),
                    template.host(),
                    0,
                    KaigiAuthorizationActionV1::HostCreate,
                    &expected_root,
                )?;
                privacy::verify_authorization(
                    state_transaction,
                    &PrivacyArtifacts {
                        commitment: commitment.as_ref(),
                        nullifier: nullifier.as_ref(),
                        roster_root: roster_root.as_ref(),
                        proof: proof.as_deref(),
                    },
                    &context,
                    None,
                )?;
            }
        }
        if let Some(manifest) = template.relay_manifest() {
            validate_relay_manifest(manifest)?;
            ensure_manifest_relays_registered(state_transaction, manifest)?;
        }
        let creation_ms = state_transaction._curr_block.creation_time().as_millis();
        let created_at_ms = u64::try_from(creation_ms).map_err(|_| {
            Error::InvariantViolation("block creation time exceeds u64::MAX milliseconds".into())
        })?;
        let mut record = KaigiRecord::from_new(&template, created_at_ms);
        if template.privacy_mode == KaigiPrivacyMode::ZkRosterV1 {
            record.host_commitment = commitment;
            if let Some(nullifier) = nullifier {
                record.push_nullifier(nullifier);
            }
        }
        store_record(state_transaction, &domain_id, key, &record)?;
        emit_status_summary(state_transaction, &record);
        emit_roster_summary(state_transaction, &record);
        if let Some(manifest) = record.relay_manifest.as_ref() {
            emit_relay_manifest_summary(state_transaction, &record.id, Some(manifest));
            #[cfg(feature = "telemetry")]
            state_transaction.telemetry.record_kaigi_manifest_update(
                &record.id.domain_id,
                "set",
                u32::try_from(manifest.hops.len()).unwrap_or(u32::MAX),
            );
        }
        emit_usage_summary(state_transaction, &record);
        Ok(())
    }
}
impl Execute for CreateKaigi {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        self.execute_authorized(
            KaigiAuthorization::SignedAccount(authority),
            state_transaction,
        )
    }
}
impl ExecuteKaigiAuthorized for JoinKaigi {
    fn execute_authorized(
        self,
        authorization: KaigiAuthorization<'_>,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let JoinKaigi {
            call_id,
            participant,
            commitment,
            nullifier,
            roster_root,
            proof,
        } = self;
        let mut commitment = commitment;
        let mut nullifier = nullifier;
        let mut roster_root = roster_root;
        let allow_unassociated = authorization.signed_account() == &participant;
        apply_with_record_authorized(
            state_transaction,
            &call_id,
            authorization,
            allow_unassociated,
            RecordUpdateEffect::Roster,
            |stx, record| {
                stx.world.account(&participant)?;
                process_join(
                    stx,
                    record,
                    authorization,
                    &participant,
                    commitment.take(),
                    nullifier.take(),
                    roster_root.take(),
                    proof.as_deref(),
                )
            },
        )?;
        Ok(())
    }
}
impl Execute for JoinKaigi {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        self.execute_authorized(
            KaigiAuthorization::SignedAccount(authority),
            state_transaction,
        )
    }
}
impl Execute for LeaveKaigi {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let LeaveKaigi {
            call_id,
            participant,
            commitment,
            nullifier,
            roster_root,
            proof,
        } = self;
        let mut commitment = commitment;
        let mut nullifier = nullifier;
        let mut roster_root = roster_root;
        apply_with_record(
            state_transaction,
            &call_id,
            authority,
            false,
            RecordUpdateEffect::Roster,
            |stx, record| {
                process_leave(
                    stx,
                    record,
                    authority,
                    &participant,
                    commitment.take(),
                    nullifier.take(),
                    roster_root.take(),
                    proof.as_deref(),
                )
            },
        )?;
        Ok(())
    }
}
impl ExecuteKaigiAuthorized for EndKaigi {
    fn execute_authorized(
        self,
        authorization: KaigiAuthorization<'_>,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let EndKaigi {
            call_id,
            ended_at_ms,
            commitment,
            nullifier,
            roster_root,
            proof,
        } = self;
        let end_ms = state_transaction._curr_block.creation_time().as_millis();
        let default_end_ms = u64::try_from(end_ms).map_err(|_| {
            Error::InvariantViolation("block creation time exceeds u64::MAX milliseconds".into())
        })?;
        let resolved_end = ended_at_ms.unwrap_or(default_end_ms);
        apply_with_record_authorized(
            state_transaction,
            &call_id,
            authorization,
            false,
            RecordUpdateEffect::Status,
            move |stx, record| {
                if record.status == KaigiStatus::Ended {
                    return Err(Error::InvariantViolation("Kaigi already ended".into()));
                }
                let authority = authorization.signed_account();
                if !accounts_share_active_lineage(stx, authority, &record.host)? {
                    return Err(unauthorized("only the host may end a Kaigi"));
                }
                if resolved_end < record.created_at_ms {
                    return Err(Error::InvalidParameter(
                        InvalidParameterError::SmartContract(
                            "Kaigi end timestamp must not precede creation".into(),
                        ),
                    ));
                }
                if resolved_end > default_end_ms {
                    return Err(Error::InvalidParameter(
                        InvalidParameterError::SmartContract(
                            "Kaigi end timestamp must not exceed the current block time".into(),
                        ),
                    ));
                }
                match record.privacy_mode {
                    KaigiPrivacyMode::Transparent => {
                        privacy::ensure_transparent_payload(&PrivacyArtifacts {
                            commitment: commitment.as_ref(),
                            nullifier: nullifier.as_ref(),
                            roster_root: roster_root.as_ref(),
                            proof: proof.as_deref(),
                        })?;
                    }
                    KaigiPrivacyMode::ZkRosterV1 => {
                        let stored = record.host_commitment.as_ref().ok_or_else(|| {
                            privacy_error("private call requires its original host commitment")
                        })?;
                        let provided_nullifier = nullifier
                            .as_ref()
                            .ok_or_else(|| privacy_error("privacy mode requires nullifier"))?;
                        if record.has_nullifier(provided_nullifier) {
                            return Err(privacy_error("nullifier already used"));
                        }
                        ensure_action_capacity_v1(
                            record.nullifier_log.len(),
                            record.roster_commitments.len(),
                            KaigiAuthorizationActionV1::HostEnd,
                        )?;
                        let context = context_from_ledger_v1(
                            *stx.network_id(),
                            &record.id,
                            &record.host,
                            &record.host,
                            0,
                            KaigiAuthorizationActionV1::HostEnd,
                            &record.roster_root(),
                        )?;
                        privacy::verify_authorization(
                            stx,
                            &PrivacyArtifacts {
                                commitment: commitment.as_ref(),
                                nullifier: Some(provided_nullifier),
                                roster_root: roster_root.as_ref(),
                                proof: proof.as_deref(),
                            },
                            &context,
                            Some(&stored.commitment),
                        )?;
                        record.push_nullifier(provided_nullifier.clone());
                    }
                }
                record.status = KaigiStatus::Ended;
                record.ended_at_ms = Some(resolved_end);
                Ok(match record.privacy_mode {
                    KaigiPrivacyMode::Transparent => AccessGrant::Default,
                    KaigiPrivacyMode::ZkRosterV1 => AccessGrant::PrivacyAuthorized,
                })
            },
        )?;
        Ok(())
    }
}
impl Execute for EndKaigi {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        self.execute_authorized(
            KaigiAuthorization::SignedAccount(authority),
            state_transaction,
        )
    }
}
impl Execute for RecordKaigiUsage {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let RecordKaigiUsage {
            call_id,
            duration_ms,
            billed_gas,
            usage_commitment,
            proof,
        } = self;
        if duration_ms == 0 {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract("usage duration must be positive".into()),
            ));
        }
        let mut usage_commitment = usage_commitment;
        apply_with_record(
            state_transaction,
            &call_id,
            authority,
            false,
            RecordUpdateEffect::Usage,
            |stx, record| {
                if !accounts_share_active_lineage(stx, authority, &record.host)? {
                    return Err(unauthorized("only the host may record usage for a Kaigi"));
                }
                ensure_kaigi_active(record)?;
                let total_duration_ms = record
                    .total_duration_ms
                    .checked_add(duration_ms)
                    .ok_or_else(|| usage_error("Kaigi total duration exceeds u64::MAX"))?;
                let total_billed_gas = record
                    .total_billed_gas
                    .checked_add(billed_gas)
                    .ok_or_else(|| usage_error("Kaigi total billed gas exceeds u64::MAX"))?;
                let segments_recorded = record
                    .segments_recorded
                    .checked_add(1)
                    .ok_or_else(|| usage_error("Kaigi usage segment count exceeds u32::MAX"))?;
                match record.privacy_mode {
                    KaigiPrivacyMode::Transparent => {
                        if usage_commitment.is_some() || proof.is_some() {
                            return Err(privacy_error(
                                "transparent Kaigi usage must not include privacy payload",
                            ));
                        }
                    }
                    KaigiPrivacyMode::ZkRosterV1 => {
                        let commitment = usage_commitment.take().ok_or_else(|| {
                            privacy_error("privacy mode requires usage commitment")
                        })?;
                        if record.usage_commitments.len() >= KAIGI_MAX_USAGE_COMMITMENTS_V1 {
                            return Err(usage_error(format!(
                                "Kaigi usage commitment log has reached its {KAIGI_MAX_USAGE_COMMITMENTS_V1}-entry limit"
                            )));
                        }
                        if record.usage_commitments.contains(&commitment) {
                            return Err(usage_error("Kaigi usage commitment already recorded"));
                        }
                        privacy::verify_usage_commitment(
                            stx,
                            record,
                            duration_ms,
                            billed_gas,
                            proof.as_deref(),
                            &commitment,
                        )?;
                        record.push_usage_commitment(commitment);
                    }
                }
                record.total_duration_ms = total_duration_ms;
                record.total_billed_gas = total_billed_gas;
                record.segments_recorded = segments_recorded;
                Ok(AccessGrant::Default)
            },
        )?;
        Ok(())
    }
}
impl Execute for SetKaigiRelayManifest {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let SetKaigiRelayManifest {
            call_id,
            relay_manifest,
        } = self;
        let mut relay_manifest = relay_manifest;
        apply_with_record(
            state_transaction,
            &call_id,
            authority,
            false,
            RecordUpdateEffect::RelayManifest,
            |stx, record| {
                if !accounts_share_active_lineage(stx, authority, &record.host)? {
                    return Err(unauthorized(
                        "only the host may update the Kaigi relay manifest",
                    ));
                }
                ensure_kaigi_active(record)?;
                let previous_manifest = record.relay_manifest.clone();
                if let Some(manifest) = relay_manifest.take() {
                    validate_relay_manifest(&manifest)?;
                    ensure_manifest_relays_registered(stx, &manifest)?;
                    if previous_manifest.as_ref() == Some(&manifest) {
                        return Ok(AccessGrant::NoRecordUpdate);
                    }
                    record.set_relay_manifest(Some(manifest));
                } else {
                    if previous_manifest.is_none() {
                        return Ok(AccessGrant::NoRecordUpdate);
                    }
                    record.set_relay_manifest(None);
                }
                Ok(AccessGrant::Default)
            },
        )?;
        Ok(())
    }
}
impl Execute for RegisterKaigiRelay {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let registration = self.relay;
        if authority != &registration.relay_id {
            return Err(unauthorized(
                "only the relay account may register or update itself",
            ));
        }
        state_transaction.world.account(authority)?;
        validate_relay_hpke_public_key(&registration.hpke_public_key)?;
        if registration.bandwidth_class == 0 {
            return Err(relay_error(
                "relay registration requires a non-zero bandwidth class",
            ));
        }
        let rekey_graph =
            persisted_kaigi_rekey_graph(&state_transaction.world, [registration.relay_id.clone()])?;
        let key = kaigi_relay_metadata_key(&registration.relay_id).map_err(|err| {
            Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
        })?;
        let domain_id =
            relay_domain_with_graph(state_transaction, &registration.relay_id, &rekey_graph)?;
        let existing = state_transaction
            .world
            .domain(&domain_id)?
            .metadata()
            .get(&key)
            .map(|value| decode_stored_relay_registration(&domain_id, &key, value))
            .transpose()
            .map_err(|error| {
                state_transaction
                    .world
                    .attempt_error_to_instruction_error(error)
            })?;
        let indexed_domain = state_transaction
            .world
            .kaigi_relay_registry
            .get(&registration.relay_id);
        match (existing.is_some(), indexed_domain) {
            (true, Some(indexed_domain)) if indexed_domain == &domain_id => {}
            (false, None) => {}
            _ => {
                return Err(Error::InvariantViolation(
                    "Kaigi relay metadata and registry index disagree".into(),
                ));
            }
        }
        let dependency = (
            KAIGI_DEPENDENCY_RELAY_REGISTRATION,
            domain_id.clone(),
            key.clone(),
        );
        let previous_dependencies = if existing.is_some() {
            BTreeSet::from([registration.relay_id.clone()])
        } else {
            BTreeSet::new()
        };
        let next_dependencies = BTreeSet::from([registration.relay_id.clone()]);
        if existing.as_ref() == Some(&registration) {
            ensure_kaigi_account_dependency_replacement(
                state_transaction,
                &dependency,
                &previous_dependencies,
                &next_dependencies,
            )?;
            return Ok(());
        }
        if existing
            .as_ref()
            .is_some_and(|current| current.hpke_public_key != registration.hpke_public_key)
        {
            relay_lifecycle_guard_v1::ensure_no_active_manifest_reference(
                state_transaction,
                &registration.relay_id,
                "rotate the HPKE key for",
            )?;
        }
        ensure_relay_allowed_by_governance_with_graph(
            state_transaction,
            &registration.relay_id,
            &rekey_graph,
        )?;
        if existing.is_none()
            && state_transaction.world.kaigi_relay_registry.len()
                >= KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1
        {
            return Err(relay_error(format!(
                "Kaigi relay registry is at its {KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1}-entry limit"
            )));
        }
        let value = Json::try_new(registration.clone())
            .map_err(|error| {
                norito_decode_attempt_error(error, |error| Error::Conversion(error.to_string()))
            })
            .map_err(|error| {
                state_transaction
                    .world
                    .attempt_error_to_instruction_error(error)
            })?;
        limits::enforce_json_size(
            state_transaction,
            &value,
            "max_metadata_value_bytes",
            limits::DEFAULT_JSON_LIMIT,
        )?;
        ensure_kaigi_account_dependency_replacement(
            state_transaction,
            &dependency,
            &previous_dependencies,
            &next_dependencies,
        )?;
        {
            let domain = state_transaction.world.domain_mut(&domain_id)?;
            domain.metadata_mut().insert(key.clone(), value.clone());
        }
        if existing.is_none() {
            let replaced = state_transaction
                .world
                .kaigi_relay_registry
                .insert(registration.relay_id.clone(), domain_id.clone());
            debug_assert!(replaced.is_none());
        }
        apply_kaigi_account_dependency_replacement(
            state_transaction,
            &dependency,
            &previous_dependencies,
            &next_dependencies,
        );
        state_transaction
            .world
            .emit_internal_events(Some(DomainEvent::MetadataInserted(MetadataChanged {
                target: domain_id.clone(),
                key,
                value: value.clone(),
            })));
        emit_relay_registration_summary(state_transaction, &domain_id, &registration);
        #[cfg(feature = "telemetry")]
        state_transaction
            .telemetry
            .record_kaigi_relay_registration(&domain_id, registration.bandwidth_class);
        Ok(())
    }
}
impl Execute for UnregisterKaigiRelay {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        state_transaction.world.account(authority)?;
        let rekey_graph = persisted_kaigi_rekey_graph(
            &state_transaction.world,
            [authority.clone(), self.relay_id.clone()],
        )?;
        if !accounts_share_active_lineage_with_graph(
            state_transaction,
            authority,
            &self.relay_id,
            &rekey_graph,
        )? {
            return Err(unauthorized(
                "only the relay account or its active account-id rekey successor may unregister it",
            ));
        }
        let domain_id =
            relay_domain_from_persisted_graph(state_transaction, &self.relay_id, &rekey_graph)?;
        let registration_key = kaigi_relay_metadata_key(&self.relay_id).map_err(|err| {
            Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
        })?;
        let indexed_domain = state_transaction
            .world
            .kaigi_relay_registry
            .get(&self.relay_id)
            .ok_or_else(|| Error::Find(FindError::MetadataKey(registration_key.clone())))?;
        if indexed_domain != &domain_id {
            return Err(Error::InvariantViolation(
                "Kaigi relay metadata and registry index disagree".into(),
            ));
        }
        let registration_value = state_transaction
            .world
            .domain(&domain_id)?
            .metadata()
            .get(&registration_key)
            .cloned()
            .ok_or_else(|| Error::Find(FindError::MetadataKey(registration_key.clone())))?;
        let registration =
            decode_stored_relay_registration(&domain_id, &registration_key, &registration_value)
                .map_err(|error| {
                    state_transaction
                        .world
                        .attempt_error_to_instruction_error(error)
                })?;
        if registration.relay_id != self.relay_id {
            return Err(Error::InvariantViolation(
                "stored Kaigi relay registration identifier does not match unregister target"
                    .into(),
            ));
        }
        let feedback_key = kaigi_relay_feedback_key(&self.relay_id).map_err(|err| {
            Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
        })?;
        let feedback_value = state_transaction
            .world
            .domain(&domain_id)?
            .metadata()
            .get(&feedback_key)
            .cloned();
        if let Some(value) = feedback_value.as_ref() {
            let feedback = decode_stored_relay_feedback(&domain_id, &feedback_key, value).map_err(
                |error| {
                    state_transaction
                        .world
                        .attempt_error_to_instruction_error(error)
                },
            )?;
            if feedback.relay_id != self.relay_id {
                return Err(Error::InvariantViolation(
                    "stored Kaigi relay feedback identifier does not match unregister target"
                        .into(),
                ));
            }
        }
        relay_lifecycle_guard_v1::ensure_no_active_manifest_reference(
            state_transaction,
            &self.relay_id,
            "unregister",
        )?;

        let registration_dependency = (
            KAIGI_DEPENDENCY_RELAY_REGISTRATION,
            domain_id.clone(),
            registration_key.clone(),
        );
        let relay_account = BTreeSet::from([self.relay_id.clone()]);
        let no_accounts = BTreeSet::new();
        ensure_kaigi_account_dependency_replacement(
            state_transaction,
            &registration_dependency,
            &relay_account,
            &no_accounts,
        )?;
        let feedback_dependency = (
            KAIGI_DEPENDENCY_RELAY_FEEDBACK,
            domain_id.clone(),
            feedback_key.clone(),
        );
        if feedback_value.is_some() {
            ensure_kaigi_account_dependency_replacement(
                state_transaction,
                &feedback_dependency,
                &relay_account,
                &no_accounts,
            )?;
        }

        {
            let domain = state_transaction.world.domain_mut(&domain_id)?;
            domain.metadata_mut().remove(&registration_key);
            if feedback_value.is_some() {
                domain.metadata_mut().remove(&feedback_key);
            }
        }
        let removed = state_transaction
            .world
            .kaigi_relay_registry
            .remove(self.relay_id.clone());
        debug_assert_eq!(removed.as_ref(), Some(&domain_id));
        apply_kaigi_account_dependency_replacement(
            state_transaction,
            &registration_dependency,
            &relay_account,
            &no_accounts,
        );
        if feedback_value.is_some() {
            apply_kaigi_account_dependency_replacement(
                state_transaction,
                &feedback_dependency,
                &relay_account,
                &no_accounts,
            );
        }
        let mut internal_events = vec![DomainEvent::MetadataRemoved(MetadataChanged {
            target: domain_id.clone(),
            key: registration_key,
            value: registration_value,
        })];
        if let Some(value) = feedback_value {
            internal_events.push(DomainEvent::MetadataRemoved(MetadataChanged {
                target: domain_id.clone(),
                key: feedback_key,
                value,
            }));
        }
        state_transaction
            .world
            .emit_internal_events(internal_events);
        emit_relay_unregistration_summary(state_transaction, &domain_id, &self.relay_id);
        Ok(())
    }
}
impl Execute for ReportKaigiRelayHealth {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let ReportKaigiRelayHealth {
            call_id,
            relay_id,
            status,
            reported_at_ms,
            notes,
        } = self;
        if let Some(ref text) = notes
            && text.chars().count() > KAIGI_RELAY_HEALTH_NOTES_MAX_CHARS_V1
        {
            return Err(relay_error(format!(
                "relay health notes must not exceed {KAIGI_RELAY_HEALTH_NOTES_MAX_CHARS_V1} characters"
            )));
        }
        apply_with_record(
            state_transaction,
            &call_id,
            authority,
            false,
            RecordUpdateEffect::None,
            |stx, record| {
                if !accounts_share_active_lineage(stx, authority, &record.host)? {
                    return Err(unauthorized("only the host may report Kaigi relay health"));
                }
                ensure_kaigi_active(record)?;
                let manifest_contains_relay =
                    record.relay_manifest.as_ref().is_some_and(|manifest| {
                        manifest.hops.iter().any(|hop| hop.relay_id == relay_id)
                    });
                if !manifest_contains_relay {
                    return Err(relay_error(
                        "relay health updates require the relay to appear in the active manifest",
                    ));
                }
                if reported_at_ms < record.created_at_ms {
                    return Err(relay_error(
                        "relay health report timestamp precedes Kaigi creation",
                    ));
                }
                if reported_at_ms > stx.block_unix_timestamp_ms() {
                    return Err(relay_error(
                        "relay health report timestamp exceeds the current block time",
                    ));
                }
                let feedback = KaigiRelayFeedback {
                    relay_id: relay_id.clone(),
                    call: record.id.clone(),
                    reported_by: authority.clone(),
                    status,
                    reported_at_ms,
                    notes: notes.clone(),
                };
                if let Some(current) = load_relay_feedback(stx, &relay_id)? {
                    if feedback.reported_at_ms < current.reported_at_ms {
                        return Err(relay_error(
                            "relay health report is older than the latest stored feedback",
                        ));
                    }
                    if feedback.reported_at_ms == current.reported_at_ms {
                        if feedback == current {
                            return Ok(AccessGrant::NoRecordUpdate);
                        }
                        return Err(relay_error(
                            "relay health report conflicts with stored feedback at the same timestamp",
                        ));
                    }
                }
                let relay_domain = store_relay_feedback(stx, &feedback)?;
                emit_relay_health_summary(stx, &relay_domain, &feedback);
                #[cfg(feature = "telemetry")]
                stx.telemetry
                    .record_kaigi_relay_health(&relay_domain, &relay_id, status);
                Ok(AccessGrant::NoRecordUpdate)
            },
        )?;
        Ok(())
    }
}
fn apply_with_record<F>(
    state_transaction: &mut StateTransaction<'_, '_>,
    call_id: &KaigiId,
    authority: &AccountId,
    allow_unassociated: bool,
    update_effect: RecordUpdateEffect,
    f: F,
) -> Result<(), Error>
where
    F: FnMut(&mut StateTransaction<'_, '_>, &mut KaigiRecord) -> Result<AccessGrant, Error>,
{
    apply_with_record_authorized(
        state_transaction,
        call_id,
        KaigiAuthorization::SignedAccount(authority),
        allow_unassociated,
        update_effect,
        f,
    )
}
fn apply_with_record_authorized<F>(
    state_transaction: &mut StateTransaction<'_, '_>,
    call_id: &KaigiId,
    authorization: KaigiAuthorization<'_>,
    allow_unassociated: bool,
    update_effect: RecordUpdateEffect,
    mut f: F,
) -> Result<(), Error>
where
    F: FnMut(&mut StateTransaction<'_, '_>, &mut KaigiRecord) -> Result<AccessGrant, Error>,
{
    let key = metadata_key(call_id)?;
    let domain_id = call_id.domain_id.clone();
    let mut record = {
        let domain = state_transaction.world.domain(&domain_id)?;
        let current = domain
            .metadata()
            .get(&key)
            .ok_or_else(|| Error::Find(FindError::MetadataKey(key.clone())))?;
        decode_stored_kaigi_record(&domain_id, &key, current).map_err(|error| {
            state_transaction
                .world
                .attempt_error_to_instruction_error(error)
        })?
    };
    let previous_dependencies = active_call_dependency_accounts(&record);
    #[cfg(feature = "telemetry")]
    let previous_manifest = record.relay_manifest.clone();
    let authority = authorization.signed_account();
    let rekey_graph = persisted_kaigi_rekey_graph(&state_transaction.world, [authority.clone()])?;
    let mut associated = if allow_unassociated {
        false
    } else {
        accounts_share_active_lineage_with_graph(
            state_transaction,
            authority,
            &record.host,
            &rekey_graph,
        )? || record_has_participant_in_active_lineage(
            state_transaction,
            &record,
            authority,
            &rekey_graph,
        )?
    };
    let grant: AccessGrant = f(state_transaction, &mut record)?;
    if matches!(grant, AccessGrant::PrivacyAuthorized) {
        associated = true;
    }
    if !allow_unassociated && !associated {
        return Err(unauthorized("account is not associated with the Kaigi"));
    }
    if matches!(grant, AccessGrant::NoRecordUpdate) {
        return Ok(());
    }
    store_record_with_previous_dependencies(
        state_transaction,
        &domain_id,
        key,
        &record,
        Some(&previous_dependencies),
    )?;
    match update_effect {
        RecordUpdateEffect::None => {}
        RecordUpdateEffect::Roster => emit_roster_summary(state_transaction, &record),
        RecordUpdateEffect::Usage => emit_usage_summary(state_transaction, &record),
        RecordUpdateEffect::RelayManifest => {
            emit_relay_manifest_summary(
                state_transaction,
                &record.id,
                record.relay_manifest.as_ref(),
            );
            #[cfg(feature = "telemetry")]
            {
                let hop_count = record.relay_manifest.as_ref().map_or(0, |manifest| {
                    u32::try_from(manifest.hops.len()).unwrap_or(u32::MAX)
                });
                let action_label =
                    match (previous_manifest.as_ref(), record.relay_manifest.as_ref()) {
                        (_, None) => "clear",
                        (None, Some(_)) => "set",
                        (Some(previous), Some(current)) if previous == current => "set",
                        (Some(_), Some(_)) => "rotate",
                    };
                state_transaction.telemetry.record_kaigi_manifest_update(
                    &record.id.domain_id,
                    action_label,
                    hop_count,
                );
                if action_label == "rotate" {
                    state_transaction.telemetry.record_kaigi_failover(
                        &record.id.domain_id,
                        &record.id.call_name,
                        hop_count,
                    );
                }
            }
        }
        RecordUpdateEffect::Status => emit_status_summary(state_transaction, &record),
    }
    Ok(())
}
fn store_record(
    state_transaction: &mut StateTransaction<'_, '_>,
    domain_id: &DomainId,
    key: Name,
    record: &KaigiRecord,
) -> Result<(), Error> {
    store_record_with_previous_dependencies(state_transaction, domain_id, key, record, None)
}
fn store_record_with_previous_dependencies(
    state_transaction: &mut StateTransaction<'_, '_>,
    domain_id: &DomainId,
    key: Name,
    record: &KaigiRecord,
    known_previous_dependencies: Option<&BTreeSet<AccountId>>,
) -> Result<(), Error> {
    validate_kaigi_record_v1(record).map_err(|message| {
        Error::InvalidParameter(InvalidParameterError::SmartContract(message))
    })?;
    let value = Json::try_new(record.clone())
        .map_err(|error| {
            norito_decode_attempt_error(error, |error| Error::Conversion(error.to_string()))
        })
        .map_err(|error| {
            state_transaction
                .world
                .attempt_error_to_instruction_error(error)
        })?;
    ensure_kaigi_json_size(&value, KAIGI_RECORD_MAX_JSON_BYTES_V1, "Kaigi call record").map_err(
        |message| Error::InvalidParameter(InvalidParameterError::SmartContract(message)),
    )?;
    limits::enforce_json_size(
        state_transaction,
        &value,
        "max_metadata_value_bytes",
        limits::DEFAULT_JSON_LIMIT,
    )?;
    storage_reservation_v1::enforce(state_transaction, record, &value)?;
    let previous_dependencies = if let Some(previous) = known_previous_dependencies {
        previous.clone()
    } else {
        state_transaction
            .world
            .domain(domain_id)?
            .metadata()
            .get(&key)
            .map(|value| {
                decode_stored_kaigi_record(domain_id, &key, value)
                    .map(|record| active_call_dependency_accounts(&record))
            })
            .transpose()
            .map_err(|error| {
                state_transaction
                    .world
                    .attempt_error_to_instruction_error(error)
            })?
            .unwrap_or_default()
    };
    let next_dependencies = active_call_dependency_accounts(record);
    let dependency = (KAIGI_DEPENDENCY_ACTIVE_CALL, domain_id.clone(), key.clone());
    ensure_kaigi_account_dependency_replacement(
        state_transaction,
        &dependency,
        &previous_dependencies,
        &next_dependencies,
    )?;
    let domain = state_transaction.world.domain_mut(domain_id)?;
    domain.metadata_mut().insert(key.clone(), value.clone());
    apply_kaigi_account_dependency_replacement(
        state_transaction,
        &dependency,
        &previous_dependencies,
        &next_dependencies,
    );
    state_transaction
        .world
        .emit_internal_events(Some(DomainEvent::MetadataInserted(MetadataChanged {
            target: domain_id.clone(),
            key,
            value,
        })));
    Ok(())
}

/// Store a Kaigi fixture through the same metadata and reverse-index path as production.
#[cfg(test)]
pub(crate) fn store_kaigi_record_for_testing(
    state_transaction: &mut StateTransaction<'_, '_>,
    record: &KaigiRecord,
) -> Result<(), Error> {
    let domain_id = record.id.domain_id.clone();
    let key = metadata_key(&record.id)?;
    store_record(state_transaction, &domain_id, key, record)
}

fn ensure_kaigi_json_size(value: &Json, limit: usize, label: &str) -> Result<(), String> {
    ensure_kaigi_json_len(value.as_ref().len(), limit, label)
}
fn ensure_kaigi_json_len(actual: usize, limit: usize, label: &str) -> Result<(), String> {
    if actual > limit {
        return Err(format!(
            "{label} exceeds the V1 {limit}-byte JSON limit (actual {actual})"
        ));
    }
    Ok(())
}
fn validate_kaigi_record_v1(record: &KaigiRecord) -> Result<(), String> {
    let participant_limit = match record.max_participants {
        Some(0) => return Err("Kaigi max_participants must be greater than zero".into()),
        Some(limit) => {
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            if limit > KAIGI_MAX_PARTICIPANTS_V1 {
                return Err(format!(
                    "Kaigi max_participants must not exceed {KAIGI_MAX_PARTICIPANTS_V1}"
                ));
            }
            limit
        }
        None => KAIGI_MAX_PARTICIPANTS_V1,
    };
    if record.participants.len() > participant_limit {
        return Err(format!(
            "Kaigi participants exceed the effective {participant_limit}-entry limit"
        ));
    }
    if record
        .participants
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err("Kaigi participants must be strictly sorted and unique".into());
    }
    if record.participants.binary_search(&record.host).is_ok() {
        return Err("Kaigi participants must not include the host account".into());
    }
    if record
        .billing_account
        .as_ref()
        .is_some_and(|billing_account| billing_account != &record.host)
    {
        return Err(
            "Kaigi billing account must equal the host until delegated billing is supported".into(),
        );
    }
    if record.roster_commitments.len() > participant_limit {
        return Err(format!(
            "Kaigi roster commitments exceed the effective {participant_limit}-entry limit"
        ));
    }
    let mut commitments = BTreeSet::new();
    if record
        .roster_commitments
        .iter()
        .any(|entry| !commitments.insert(&entry.commitment))
    {
        return Err("Kaigi roster commitments must be unique".into());
    }
    if record.nullifier_log.len() > KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1 {
        return Err(format!(
            "Kaigi nullifier log exceeds the {KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1}-entry limit"
        ));
    }
    let mut nullifiers = BTreeSet::new();
    if record
        .nullifier_log
        .iter()
        .any(|entry| !nullifiers.insert(&entry.digest))
    {
        return Err("Kaigi nullifiers must be unique".into());
    }
    if record.usage_commitments.len() > KAIGI_MAX_USAGE_COMMITMENTS_V1 {
        return Err(format!(
            "Kaigi usage commitments exceed the {KAIGI_MAX_USAGE_COMMITMENTS_V1}-entry limit"
        ));
    }
    let mut usage_commitments = BTreeSet::new();
    if record
        .usage_commitments
        .iter()
        .any(|commitment| !usage_commitments.insert(commitment))
    {
        return Err("Kaigi usage commitments must be unique".into());
    }
    if record.roster_root != KaigiRecord::compute_roster_root(&record.roster_commitments) {
        return Err("Kaigi roster root does not match the retained roster commitments".into());
    }
    match (record.status, record.ended_at_ms) {
        (KaigiStatus::Active, None) => {}
        (KaigiStatus::Ended, Some(ended_at_ms)) if ended_at_ms >= record.created_at_ms => {}
        (KaigiStatus::Ended, Some(_)) => {
            return Err("Kaigi end timestamp must not precede creation".into());
        }
        (KaigiStatus::Active, Some(_)) => {
            return Err("active Kaigi record must not retain an end timestamp".into());
        }
        (KaigiStatus::Ended, None) => {
            return Err("ended Kaigi record must retain an end timestamp".into());
        }
    }
    match record.privacy_mode {
        KaigiPrivacyMode::Transparent => {
            if record.host_commitment.is_some()
                || !record.roster_commitments.is_empty()
                || !record.nullifier_log.is_empty()
                || !record.usage_commitments.is_empty()
                || !record.private_participation.entries().is_empty()
            {
                return Err(
                    "transparent Kaigi record must not retain private roster artifacts".into(),
                );
            }
        }
        KaigiPrivacyMode::ZkRosterV1 => {
            let host_commitment = record
                .host_commitment
                .as_ref()
                .ok_or("private Kaigi record requires its original host commitment")?;
            if record.nullifier_log.is_empty() {
                return Err("private Kaigi record requires host-create nullifier".into());
            }
            if record
                .roster_commitments
                .iter()
                .any(|entry| entry.commitment == host_commitment.commitment)
                || record
                    .private_participation
                    .entries()
                    .iter()
                    .any(|entry| entry.original_account() == &record.host)
            {
                return Err("host must not own participant membership".into());
            }
            record
                .private_participation
                .validate_against_roster(
                    &record
                        .roster_commitments
                        .iter()
                        .map(|entry| entry.commitment)
                        .collect::<Vec<_>>(),
                )
                .map_err(|error| error.to_string())?;
            if record.status == KaigiStatus::Active
                && record
                    .nullifier_log
                    .len()
                    .checked_add(record.roster_commitments.len())
                    .and_then(|count| count.checked_add(1))
                    .is_none_or(|count| count > KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1)
            {
                return Err(
                    "private Kaigi history must reserve every live leave and host end".into(),
                );
            }
            if !record.participants.is_empty() {
                return Err(
                    "private Kaigi record must not retain transparent participant IDs".into(),
                );
            }
        }
    }
    if record.participant_metadata.len() > participant_limit.saturating_add(1) {
        return Err(format!(
            "Kaigi participant metadata exceeds the effective {}-entry limit",
            participant_limit.saturating_add(1)
        ));
    }
    if record.participant_metadata.keys().any(|account| {
        account != &record.host && record.participants.binary_search(account).is_err()
    }) {
        return Err(
            "Kaigi participant metadata must reference the host or a current participant".into(),
        );
    }
    if record.privacy_mode == KaigiPrivacyMode::ZkRosterV1
        && usize::try_from(record.segments_recorded).unwrap_or(usize::MAX)
            != record.usage_commitments.len()
    {
        return Err(
            "private Kaigi usage segment count must match retained usage commitments".into(),
        );
    }
    Ok(())
}
fn decode_stored_kaigi_record(
    domain_id: &DomainId,
    key: &Name,
    value: &Json,
) -> Result<KaigiRecord, ExecutionAttemptError<Error>> {
    ensure_kaigi_json_size(
        value,
        KAIGI_RECORD_MAX_JSON_BYTES_V1,
        "stored Kaigi call record",
    )
    .map_err(|message| Error::InvariantViolation(message.into()))?;
    // Keep the borrowed canonical Json and classify its original refusal before any
    // diagnostic projection or caller unwind. The current caller owns the codec scope.
    // TODO(S6): ordinary KaigiRecord/index graphs still need original-pool physical
    // ownership; cumulative codec accounting does not admit their nested allocations.
    let record: KaigiRecord = value.try_into_any_norito().map_err(|error| {
        norito_decode_attempt_error(error, |error| {
            Error::InvariantViolation(
                format!("malformed Kaigi record in domain {domain_id}: {error}").into(),
            )
        })
    })?;
    let expected_key = metadata_key(&record.id).map_err(|error| {
        Error::InvariantViolation(format!("invalid stored Kaigi identity: {error}").into())
    })?;
    if &record.id.domain_id != domain_id || &expected_key != key {
        return Err(Error::InvariantViolation(
            "stored Kaigi record identifier does not match metadata key".into(),
        )
        .into());
    }
    validate_kaigi_record_v1(&record).map_err(|message| {
        Error::InvariantViolation(
            format!("stored Kaigi record violates V1 constraints: {message}").into(),
        )
    })?;
    if record
        .relay_manifest
        .as_ref()
        .is_some_and(|manifest| validate_relay_manifest(manifest).is_err())
    {
        return Err(Error::InvariantViolation(
            "stored Kaigi relay manifest violates V1 constraints".into(),
        )
        .into());
    }
    Ok(record)
}
fn store_relay_feedback(
    state_transaction: &mut StateTransaction<'_, '_>,
    feedback: &KaigiRelayFeedback,
) -> Result<DomainId, Error> {
    let key = kaigi_relay_feedback_key(&feedback.relay_id).map_err(|err| {
        Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
    })?;
    let value = Json::try_new(feedback.clone())
        .map_err(|error| {
            norito_decode_attempt_error(error, |error| Error::Conversion(error.to_string()))
        })
        .map_err(|error| {
            state_transaction
                .world
                .attempt_error_to_instruction_error(error)
        })?;
    limits::enforce_json_size(
        state_transaction,
        &value,
        "max_metadata_value_bytes",
        limits::DEFAULT_JSON_LIMIT,
    )?;
    let domain_id = relay_domain(state_transaction, &feedback.relay_id)?;
    let previous_dependencies = if state_transaction
        .world
        .domain(&domain_id)?
        .metadata()
        .contains(&key)
    {
        BTreeSet::from([feedback.relay_id.clone()])
    } else {
        BTreeSet::new()
    };
    let next_dependencies = BTreeSet::from([feedback.relay_id.clone()]);
    let dependency = (
        KAIGI_DEPENDENCY_RELAY_FEEDBACK,
        domain_id.clone(),
        key.clone(),
    );
    ensure_kaigi_account_dependency_replacement(
        state_transaction,
        &dependency,
        &previous_dependencies,
        &next_dependencies,
    )?;
    {
        let domain = state_transaction.world.domain_mut(&domain_id)?;
        domain.metadata_mut().insert(key.clone(), value.clone());
    }
    apply_kaigi_account_dependency_replacement(
        state_transaction,
        &dependency,
        &previous_dependencies,
        &next_dependencies,
    );
    state_transaction
        .world
        .emit_internal_events(Some(DomainEvent::MetadataInserted(MetadataChanged {
            target: domain_id.clone(),
            key,
            value,
        })));
    Ok(domain_id)
}

fn active_call_dependency_accounts(record: &KaigiRecord) -> BTreeSet<AccountId> {
    if record.status != KaigiStatus::Active {
        return BTreeSet::new();
    }
    let mut accounts = BTreeSet::from([record.host.clone()]);
    accounts.extend(record.participants.iter().cloned());
    accounts.extend(
        record
            .private_participation
            .entries()
            .iter()
            .map(|entry| entry.original_account().clone()),
    );
    if let Some(manifest) = record.relay_manifest.as_ref() {
        accounts.extend(manifest.hops.iter().map(|hop| hop.relay_id.clone()));
    }
    accounts
}

fn ensure_kaigi_account_dependency_replacement(
    state_transaction: &StateTransaction<'_, '_>,
    dependency: &KaigiAccountDependencyLocator,
    previous_accounts: &BTreeSet<AccountId>,
    next_accounts: &BTreeSet<AccountId>,
) -> Result<(), Error> {
    for account in previous_accounts.union(next_accounts) {
        let indexed = state_transaction
            .world
            .kaigi_account_dependencies
            .get(account)
            .is_some_and(|dependencies| dependencies.contains(dependency));
        if indexed != previous_accounts.contains(account) {
            return Err(Error::InvariantViolation(
                "Kaigi account-dependency index disagrees with authoritative metadata".into(),
            ));
        }
    }
    Ok(())
}

fn apply_kaigi_account_dependency_replacement(
    state_transaction: &mut StateTransaction<'_, '_>,
    dependency: &KaigiAccountDependencyLocator,
    previous_accounts: &BTreeSet<AccountId>,
    next_accounts: &BTreeSet<AccountId>,
) {
    for account in previous_accounts.difference(next_accounts) {
        let remove_account = state_transaction
            .world
            .kaigi_account_dependencies
            .get_mut(account)
            .is_some_and(|dependencies| {
                dependencies.remove(dependency);
                dependencies.is_empty()
            });
        if remove_account {
            state_transaction
                .world
                .kaigi_account_dependencies
                .remove(account.clone());
        }
    }
    for account in next_accounts.difference(previous_accounts) {
        if state_transaction
            .world
            .kaigi_account_dependencies
            .get(account)
            .is_none()
        {
            state_transaction
                .world
                .kaigi_account_dependencies
                .insert(account.clone(), BTreeSet::new());
        }
        state_transaction
            .world
            .kaigi_account_dependencies
            .get_mut(account)
            .expect("Kaigi dependency account was just inserted")
            .insert(dependency.clone());
    }
}
fn metadata_key(call_id: &KaigiId) -> Result<Name, Error> {
    kaigi_metadata_key(&call_id.call_name).map_err(|err| {
        Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
    })
}
/// Return whether a domain metadata key is owned by native Kaigi state.
///
/// The governance-managed relay allowlist deliberately remains outside these
/// prefixes so domain governance can update it through ordinary metadata ISIs.
pub(crate) fn is_reserved_kaigi_metadata_key(key: &Name) -> bool {
    let literal = key.as_ref();
    literal.starts_with("kaigi__")
        || literal.starts_with("kaigi_relay__")
        || literal.starts_with("kaigi_relay_feedback__")
}

enum IndexedKaigiDependency {
    ActiveCall(KaigiRecord),
    RelayRegistration,
    RelayFeedback,
}

fn validate_indexed_kaigi_dependency(
    world: &impl WorldReadOnly,
    indexed_account: &AccountId,
    dependency: &KaigiAccountDependencyLocator,
) -> Result<IndexedKaigiDependency, ExecutionAttemptError<Error>> {
    let (kind, domain_id, key) = dependency;
    let domain = world.domain(domain_id).map_err(Error::from)?;
    let value = domain.metadata().get(key).ok_or_else(|| {
        Error::InvariantViolation(
            "Kaigi account-dependency index references missing metadata".into(),
        )
    })?;
    match *kind {
        KAIGI_DEPENDENCY_RELAY_REGISTRATION => {
            let registration = decode_stored_relay_registration(domain_id, key, value)?;
            if &registration.relay_id != indexed_account {
                return Err(Error::InvariantViolation(
                    "Kaigi relay dependency is indexed under the wrong account".into(),
                )
                .into());
            }
            Ok(IndexedKaigiDependency::RelayRegistration)
        }
        KAIGI_DEPENDENCY_RELAY_FEEDBACK => {
            let feedback = decode_stored_relay_feedback(domain_id, key, value)?;
            if &feedback.relay_id != indexed_account {
                return Err(Error::InvariantViolation(
                    "Kaigi relay feedback dependency is indexed under the wrong account".into(),
                )
                .into());
            }
            Ok(IndexedKaigiDependency::RelayFeedback)
        }
        KAIGI_DEPENDENCY_ACTIVE_CALL => {
            let record = decode_stored_kaigi_record(domain_id, key, value)?;
            if !active_call_dependency_accounts(&record).contains(indexed_account) {
                return Err(Error::InvariantViolation(
                    "Kaigi call dependency is indexed under the wrong account or metadata location"
                        .into(),
                )
                .into());
            }
            Ok(IndexedKaigiDependency::ActiveCall(record))
        }
        _ => Err(Error::InvariantViolation(
            "Kaigi account-dependency index contains an unknown dependency kind".into(),
        )
        .into()),
    }
}

/// Reject moving a registered relay's primary alias outside its storage domain.
///
/// Relay descriptors and feedback are domain metadata keyed by the relay ID.
/// A relay must execute `UnregisterKaigiRelay` before changing its primary alias
/// domain so protected state is not stranded in the previous domain.
pub(crate) fn ensure_kaigi_relay_home_change_allowed(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
    current_domain: &DomainId,
    new_domain: Option<&DomainId>,
) -> Result<(), Error> {
    if new_domain == Some(current_domain) {
        return Ok(());
    }
    let rekey_graph = persisted_kaigi_rekey_graph(&state_transaction.world, [account.clone()])?;
    let component = persisted_kaigi_rekey_component(&rekey_graph.neighbours, account);
    for identity in component {
        let Some(dependencies) = state_transaction
            .world
            .kaigi_account_dependencies
            .get(&identity)
        else {
            continue;
        };
        for dependency in dependencies
            .iter()
            .take_while(|(kind, _, _)| *kind < KAIGI_DEPENDENCY_ACTIVE_CALL)
        {
            validate_indexed_kaigi_dependency(&state_transaction.world, &identity, dependency)
                .map_err(|error| {
                    state_transaction
                        .world
                        .attempt_error_to_instruction_error(error)
                })?;
            if &dependency.1 != current_domain {
                continue;
            }
            if !accounts_share_active_lineage_with_graph(
                state_transaction,
                account,
                &identity,
                &rekey_graph,
            )? {
                continue;
            }
            return Err(relay_error(
                "registered Kaigi relay primary alias domain is pinned while relay state exists",
            ));
        }
    }
    Ok(())
}
/// Reject account removal while native Kaigi state still depends on the account.
pub(crate) fn ensure_kaigi_account_can_unregister(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), Error> {
    let aliases = state_transaction
        .world
        .account_aliases_by_account
        .get(account)
        .cloned()
        .unwrap_or_default();
    ensure_kaigi_account_rekey_records_can_be_removed(
        state_transaction,
        &aliases,
        "unregistering the alias owner",
    )?;
    ensure_kaigi_account_has_no_stranded_dependencies(state_transaction, account, "unregister")
}
/// Reject an aliasless account-id rekey while native Kaigi state needs durable continuity.
pub(crate) fn ensure_kaigi_account_can_rekey_without_continuity(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), Error> {
    ensure_kaigi_account_has_no_stranded_dependencies(
        state_transaction,
        account,
        "rekey without durable account-alias continuity for",
    )
}
fn ensure_kaigi_account_has_no_stranded_dependencies(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
    operation: &str,
) -> Result<(), Error> {
    let rekey_graph = persisted_kaigi_rekey_graph(&state_transaction.world, [account.clone()])?;
    let component = persisted_kaigi_rekey_component(&rekey_graph.neighbours, account);
    ensure_kaigi_rekey_component_has_no_stranded_dependencies(
        state_transaction,
        account,
        &component,
        &rekey_graph,
        operation,
    )
}
fn ensure_kaigi_rekey_component_has_no_stranded_dependencies(
    state_transaction: &StateTransaction<'_, '_>,
    representative: &AccountId,
    component: &BTreeSet<AccountId>,
    rekey_graph: &PersistedKaigiRekeyGraph,
    operation: &str,
) -> Result<(), Error> {
    // A validated connected component has one persisted terminal, so one representative
    // preserves the lineage check while the dependency bucket is inspected only once.
    for identity in component {
        let Some(dependency) = state_transaction
            .world
            .kaigi_account_dependencies
            .get(identity)
            .and_then(|dependencies| dependencies.iter().next())
        else {
            continue;
        };
        let indexed =
            validate_indexed_kaigi_dependency(&state_transaction.world, identity, dependency)
                .map_err(|error| {
                    state_transaction
                        .world
                        .attempt_error_to_instruction_error(error)
                })?;
        if !accounts_share_active_lineage_with_graph(
            state_transaction,
            representative,
            identity,
            rekey_graph,
        )? {
            continue;
        }
        let message = match indexed {
            IndexedKaigiDependency::ActiveCall(record) => format!(
                "cannot {operation} account {representative}: it is referenced by active Kaigi {}",
                record.id
            ),
            IndexedKaigiDependency::RelayRegistration => format!(
                "cannot {operation} account {representative}: it owns retained Kaigi relay registration"
            ),
            IndexedKaigiDependency::RelayFeedback => format!(
                "cannot {operation} account {representative}: it owns retained Kaigi relay feedback"
            ),
        };
        return Err(Error::InvariantViolation(message.into()));
    }
    Ok(())
}
/// Reject removal of alias continuity records still needed by native Kaigi state.
pub(crate) fn ensure_kaigi_account_rekey_records_can_be_removed(
    state_transaction: &StateTransaction<'_, '_>,
    aliases: &BTreeSet<AccountAlias>,
    operation: &str,
) -> Result<(), Error> {
    let mut endpoint_aliases = Vec::<(AccountId, AccountAlias)>::new();
    let mut seen_endpoints = BTreeSet::new();
    let mut retained_occurrences = 0usize;
    for alias in aliases {
        let Some(record) = state_transaction.world.account_rekey_records.get(alias) else {
            continue;
        };
        if &record.label != alias
            || record.previous_account_ids.len() != record.transition_provenance.len()
        {
            return Err(Error::InvariantViolation(
                "cannot remove malformed account-id rekey history used by Kaigi".into(),
            ));
        }
        retained_occurrences = retained_occurrences
            .checked_add(record.previous_account_ids.len().saturating_add(1))
            .filter(|work| *work <= crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT)
            .ok_or_else(|| {
                Error::InvariantViolation(
                    format!(
                        "cannot remove account alias {alias:?} while {operation}: selected account-id rekey history exceeds the deterministic {}-occurrence work limit",
                        crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT
                    )
                    .into(),
                )
            })?;
        let mut sequence = record.previous_account_ids.clone();
        sequence.push(record.active_account_id.clone());
        for (index, provenance) in record.transition_provenance.iter().enumerate() {
            if *provenance != AccountRekeyTransitionProvenance::AccountIdRekey {
                continue;
            }
            for identity in [&sequence[index], &sequence[index + 1]] {
                if seen_endpoints.insert((*identity).clone()) {
                    endpoint_aliases.push(((*identity).clone(), alias.clone()));
                }
            }
        }
    }
    let Some((_, first_alias)) = endpoint_aliases.first() else {
        return Ok(());
    };
    let wrap_error = |alias: &AccountAlias, error: Error| {
        Error::InvariantViolation(
            format!(
                "cannot remove account alias {alias:?} while {operation}: its canonical account-id rekey history is required by native Kaigi state ({error})"
            )
            .into(),
        )
    };
    let rekey_graph = persisted_kaigi_rekey_graph(
        &state_transaction.world,
        endpoint_aliases.iter().map(|(account, _)| account.clone()),
    )
    .map_err(|error| wrap_error(first_alias, error))?;
    let mut inspected_accounts = BTreeSet::new();
    for (endpoint, alias) in endpoint_aliases {
        if inspected_accounts.contains(&endpoint) {
            continue;
        }
        let component = persisted_kaigi_rekey_component(&rekey_graph.neighbours, &endpoint);
        inspected_accounts.extend(component.iter().cloned());
        ensure_kaigi_rekey_component_has_no_stranded_dependencies(
            state_transaction,
            &endpoint,
            &component,
            &rekey_graph,
            "remove retained rekey continuity for",
        )
        .map_err(|error| wrap_error(&alias, error))?;
    }
    Ok(())
}
/// Reject activating an account ID retained as a canonical rekey predecessor.
pub(crate) fn ensure_account_id_is_not_retired_rekey_predecessor(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), Error> {
    let graph = persisted_kaigi_rekey_graph(&state_transaction.world, [account.clone()])?;
    if graph.forward.contains_key(account) {
        return Err(Error::InvariantViolation(
            format!(
                "cannot activate account {account}: it is retained as a retired canonical account-id rekey predecessor"
            )
            .into(),
        ));
    }
    Ok(())
}
/// Reject domain removal while it contains protected native Kaigi state.
pub(crate) fn ensure_kaigi_domain_can_unregister(
    state_transaction: &StateTransaction<'_, '_>,
    domain_id: &DomainId,
) -> Result<(), Error> {
    let domain = state_transaction.world.domain(domain_id)?;
    if let Some((key, _)) = domain
        .metadata()
        .iter()
        .find(|(key, _)| is_reserved_kaigi_metadata_key(key))
    {
        return Err(Error::InvariantViolation(
            format!(
                "cannot unregister domain {domain_id}: it contains protected native Kaigi state at metadata key {key}"
            )
            .into(),
        ));
    }
    let account_ids = state_transaction
        .world
        .accounts_in_domain_iter(domain_id)
        .map(|account| account.id().clone())
        .collect::<Vec<_>>();
    let mut aliases = BTreeSet::new();
    for account_id in account_ids {
        let Some(account_aliases) = state_transaction
            .world
            .account_aliases_by_account
            .get(&account_id)
        else {
            continue;
        };
        for alias in account_aliases {
            let alias_domain = alias
                .domain_id(state_transaction.world.dataspace_catalog())
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!(
                            "cannot inspect account alias {alias:?} before domain teardown: {error}"
                        )
                        .into(),
                    )
                })?;
            if alias_domain.as_ref() == Some(domain_id) {
                aliases.insert(alias.clone());
            }
        }
    }
    ensure_kaigi_account_rekey_records_can_be_removed(
        state_transaction,
        &aliases,
        "unregistering its alias domain",
    )?;
    Ok(())
}
fn unauthorized(message: impl Into<String>) -> Error {
    Error::InvalidParameter(InvalidParameterError::SmartContract(message.into()))
}
fn privacy_error(message: impl Into<String>) -> Error {
    Error::InvalidParameter(InvalidParameterError::SmartContract(message.into()))
}
fn relay_error(message: impl Into<String>) -> Error {
    Error::InvalidParameter(InvalidParameterError::SmartContract(message.into()))
}
fn usage_error(message: impl Into<String>) -> Error {
    Error::InvalidParameter(InvalidParameterError::SmartContract(message.into()))
}
fn ensure_kaigi_active(record: &KaigiRecord) -> Result<(), Error> {
    if record.status != KaigiStatus::Active {
        return Err(Error::InvariantViolation("Kaigi is not active".into()));
    }
    Ok(())
}
fn resolve_active_kaigi_account(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<Option<AccountId>, Error> {
    let graph = persisted_kaigi_rekey_graph(&state_transaction.world, [account.clone()])?;
    resolve_active_kaigi_account_with_graph(state_transaction, account, &graph)
}
fn resolve_active_kaigi_account_with_graph(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<Option<AccountId>, Error> {
    let live = crate::sns::resolve_active_account_id_rekey_lineage(
        &state_transaction.world,
        state_transaction.world.dataspace_catalog(),
        account,
        state_transaction.block_unix_timestamp_ms(),
    )
    .map_err(|error| {
        state_transaction
            .world
            .attempt_error_to_instruction_error(error.into_attempt_error(|error| {
                Error::InvariantViolation(
                    format!("failed to resolve Kaigi account-id rekey lineage: {error}").into(),
                )
            }))
    })?;
    let persisted =
        resolve_persisted_kaigi_rekey_successor(&state_transaction.world, account, graph)?;
    if let (Some(live), Some(persisted)) = (&live, &persisted)
        && live != persisted
    {
        return Err(Error::InvariantViolation(
            "live and persisted account-id rekey lineage resolve to different successors".into(),
        ));
    }
    Ok(live.or(persisted))
}
fn accounts_share_active_lineage(
    state_transaction: &StateTransaction<'_, '_>,
    left: &AccountId,
    right: &AccountId,
) -> Result<bool, Error> {
    let graph =
        persisted_kaigi_rekey_graph(&state_transaction.world, [left.clone(), right.clone()])?;
    accounts_share_active_lineage_with_graph(state_transaction, left, right, &graph)
}
fn accounts_share_active_lineage_with_graph(
    state_transaction: &StateTransaction<'_, '_>,
    left: &AccountId,
    right: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<bool, Error> {
    let left_active = resolve_active_kaigi_account_with_graph(state_transaction, left, graph)?;
    let right_active = resolve_active_kaigi_account_with_graph(state_transaction, right, graph)?;
    Ok(left_active.is_some() && left_active == right_active)
}
fn resolve_persisted_kaigi_rekey_successor(
    world: &impl WorldReadOnly,
    account: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<Option<AccountId>, Error> {
    let component = persisted_kaigi_rekey_component(&graph.neighbours, account);
    let mut terminal = account.clone();
    while let Some(successor) = graph.forward.get(&terminal) {
        terminal = successor.clone();
    }
    let registered = component
        .into_iter()
        .filter(|candidate| world.account(candidate).is_ok())
        .collect::<BTreeSet<_>>();
    if registered.is_empty() {
        return Ok(None);
    }
    if registered.len() != 1 || !registered.contains(&terminal) {
        return Err(Error::InvariantViolation(
            "persisted account-id rekey history does not have one registered terminal successor"
                .into(),
        ));
    }
    Ok(Some(terminal))
}
#[derive(Default)]
struct PersistedKaigiRekeyGraph {
    forward: BTreeMap<AccountId, AccountId>,
    neighbours: BTreeMap<AccountId, BTreeSet<AccountId>>,
}
fn persisted_kaigi_rekey_graph(
    world: &impl WorldReadOnly,
    accounts: impl IntoIterator<Item = AccountId>,
) -> Result<PersistedKaigiRekeyGraph, Error> {
    let mut graph = PersistedKaigiRekeyGraph::default();
    let mut reverse = BTreeMap::<AccountId, AccountId>::new();
    let mut covered_accounts = BTreeSet::new();
    let mut work = 0usize;
    for seed in accounts {
        if covered_accounts.contains(&seed) {
            continue;
        }
        let mut frontier = vec![seed];
        let mut component_accounts = BTreeSet::new();
        let mut expanded_aliases = BTreeSet::<AccountAlias>::new();
        while let Some(account) = frontier.pop() {
            if !component_accounts.insert(account.clone()) {
                continue;
            }
            if let Some(aliases) = world.account_rekey_records_by_account().get(&account) {
                for label in aliases {
                    if expanded_aliases.contains(label) {
                        continue;
                    }
                    let record = world.account_rekey_records().get(label).ok_or_else(|| {
                        Error::InvariantViolation(
                            "account-id rekey reverse index references a missing history record"
                                .into(),
                        )
                    })?;
                    work = work
                        .checked_add(record.previous_account_ids.len().saturating_add(1))
                        .filter(|work| *work <= crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT)
                        .ok_or_else(|| {
                            Error::InvariantViolation(
                                format!(
                                    "account-id rekey lineage exceeds the deterministic {}-occurrence work limit",
                                    crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT
                                )
                                .into(),
                            )
                        })?;
                    expanded_aliases.insert(label.clone());
                    if label != &record.label {
                        return Err(Error::InvariantViolation(
                            "account-id rekey history key does not match its embedded alias".into(),
                        ));
                    }
                    if record.previous_account_ids.len() != record.transition_provenance.len() {
                        return Err(Error::InvariantViolation(
                            "malformed account-id rekey history while resolving Kaigi continuity"
                                .into(),
                        ));
                    }
                    let contains_account = record
                        .previous_account_ids
                        .iter()
                        .chain(core::iter::once(&record.active_account_id))
                        .any(|candidate| candidate == &account);
                    if !contains_account {
                        return Err(Error::InvariantViolation(
                            "account-id rekey reverse index contains a stale alias occurrence"
                                .into(),
                        ));
                    }
                    for candidate in record
                        .previous_account_ids
                        .iter()
                        .chain(core::iter::once(&record.active_account_id))
                    {
                        if !world
                            .account_rekey_records_by_account()
                            .get(candidate)
                            .is_some_and(|aliases| aliases.contains(label))
                        {
                            return Err(Error::InvariantViolation(
                                "account-id rekey history is missing a reverse alias occurrence"
                                    .into(),
                            ));
                        }
                    }
                    let mut record_edges = Vec::new();
                    let mut record_neighbours = BTreeMap::<AccountId, BTreeSet<AccountId>>::new();
                    for (index, provenance) in record.transition_provenance.iter().enumerate() {
                        if *provenance != AccountRekeyTransitionProvenance::AccountIdRekey {
                            continue;
                        }
                        let predecessor = record.previous_account_ids[index].clone();
                        let successor = record
                            .previous_account_ids
                            .get(index + 1)
                            .unwrap_or(&record.active_account_id)
                            .clone();
                        record_neighbours
                            .entry(predecessor.clone())
                            .or_default()
                            .insert(successor.clone());
                        record_neighbours
                            .entry(successor.clone())
                            .or_default()
                            .insert(predecessor.clone());
                        record_edges.push((predecessor, successor));
                    }
                    let record_component =
                        persisted_kaigi_rekey_component(&record_neighbours, &account);
                    for (predecessor, successor) in record_edges {
                        if !record_component.contains(&predecessor) {
                            continue;
                        }
                        if predecessor == successor
                            || graph
                                .forward
                                .get(&predecessor)
                                .is_some_and(|existing| existing != &successor)
                            || reverse
                                .get(&successor)
                                .is_some_and(|existing| existing != &predecessor)
                        {
                            return Err(Error::InvariantViolation(
                                "ambiguous account-id rekey history while resolving Kaigi continuity"
                                    .into(),
                            ));
                        }
                        graph.forward.insert(predecessor.clone(), successor.clone());
                        reverse.insert(successor.clone(), predecessor.clone());
                        graph
                            .neighbours
                            .entry(predecessor.clone())
                            .or_default()
                            .insert(successor.clone());
                        graph
                            .neighbours
                            .entry(successor)
                            .or_default()
                            .insert(predecessor);
                    }
                }
            }
            if let Some(neighbours) = graph.neighbours.get(&account) {
                frontier.extend(neighbours.iter().cloned());
            }
        }
        covered_accounts.extend(component_accounts);
    }
    let mut completed = BTreeSet::new();
    for start in graph.forward.keys() {
        if completed.contains(start) {
            continue;
        }
        let mut path = BTreeSet::new();
        let mut current = start;
        while let Some(successor) = graph.forward.get(current) {
            if completed.contains(current) {
                break;
            }
            if !path.insert(current.clone()) {
                return Err(Error::InvariantViolation(
                    "cyclic account-id rekey history while resolving Kaigi continuity".into(),
                ));
            }
            current = successor;
        }
        completed.extend(path);
    }
    Ok(graph)
}
fn persisted_kaigi_rekey_component(
    neighbours: &BTreeMap<AccountId, BTreeSet<AccountId>>,
    account: &AccountId,
) -> BTreeSet<AccountId> {
    let mut frontier = vec![account.clone()];
    let mut visited = BTreeSet::new();
    while let Some(account) = frontier.pop() {
        if !visited.insert(account.clone()) {
            continue;
        }
        if let Some(next) = neighbours.get(&account) {
            frontier.extend(next.iter().cloned());
        }
    }
    visited
}
fn record_has_participant_in_active_lineage(
    state_transaction: &StateTransaction<'_, '_>,
    record: &KaigiRecord,
    account: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<bool, Error> {
    if record.privacy_mode == KaigiPrivacyMode::ZkRosterV1 {
        let component = persisted_kaigi_rekey_component(&graph.neighbours, account);
        let mut owners = record
            .private_participation
            .entries()
            .iter()
            .filter(|entry| component.contains(entry.original_account()));
        let first = owners.next();
        if owners.next().is_some() {
            return Err(privacy_error(
                "multiple retained Kaigi subjects share one account rekey lineage",
            ));
        }
        return match first.filter(|entry| entry.active_commitment().is_some()) {
            Some(entry) => accounts_share_active_lineage_with_graph(
                state_transaction,
                entry.original_account(),
                account,
                graph,
            ),
            None => Ok(false),
        };
    }
    Ok(
        !record_participant_indexes_in_active_lineage(state_transaction, record, account, graph)?
            .is_empty(),
    )
}
fn record_participant_indexes_in_active_lineage(
    state_transaction: &StateTransaction<'_, '_>,
    record: &KaigiRecord,
    account: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<Vec<usize>, Error> {
    let component = persisted_kaigi_rekey_component(&graph.neighbours, account);
    let mut indexes = component
        .iter()
        .filter_map(|identity| record.participants.binary_search(identity).ok())
        .collect::<Vec<_>>();
    indexes.sort_unstable();
    indexes.dedup();
    if indexes.len() > 1 {
        return Err(Error::InvariantViolation(
            "multiple Kaigi participants resolve to the same active account-id rekey lineage"
                .into(),
        ));
    }
    if let Some(&index) = indexes.first() {
        if !accounts_share_active_lineage_with_graph(
            state_transaction,
            &record.participants[index],
            account,
            graph,
        )? {
            return Err(Error::InvariantViolation(
                "persisted Kaigi participant lineage disagrees with active account-id rekey state"
                    .into(),
            ));
        }
    }
    Ok(indexes)
}
fn validate_relay_manifest(manifest: &KaigiRelayManifest) -> Result<(), Error> {
    if manifest.hops.len() < KAIGI_RELAY_MANIFEST_MIN_HOPS_V1 {
        return Err(Error::InvalidParameter(
            InvalidParameterError::SmartContract(
                "relay manifest must include at least three hops".into(),
            ),
        ));
    }
    if manifest.hops.len() > KAIGI_RELAY_MANIFEST_MAX_HOPS_V1 {
        return Err(Error::InvalidParameter(
            InvalidParameterError::SmartContract(format!(
                "relay manifest must not include more than {KAIGI_RELAY_MANIFEST_MAX_HOPS_V1} hops"
            )),
        ));
    }
    let mut seen_relays = BTreeSet::new();
    for hop in &manifest.hops {
        validate_relay_hpke_public_key(&hop.hpke_public_key)?;
        if hop.weight == 0 {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract("relay weights must be non-zero".into()),
            ));
        }
        if !seen_relays.insert(hop.relay_id.clone()) {
            return Err(Error::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "relay manifest must not contain duplicate relays".into(),
                ),
            ));
        }
    }
    Ok(())
}
fn validate_relay_hpke_public_key(hpke_public_key: &[u8]) -> Result<(), Error> {
    if hpke_public_key.is_empty() {
        return Err(relay_error("relay HPKE public key must be non-empty"));
    }
    if hpke_public_key.len() > KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 {
        return Err(relay_error(format!(
            "relay HPKE public key must not exceed {KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1} bytes"
        )));
    }
    Ok(())
}
fn decode_stored_relay_registration(
    domain_id: &DomainId,
    key: &Name,
    value: &Json,
) -> Result<KaigiRelayRegistration, ExecutionAttemptError<Error>> {
    // TODO(S6): relay/index graphs still require original-pool physical custody;
    // preserving the caller's codec refusal does not admit their nested allocations.
    let registration: KaigiRelayRegistration = value.try_into_any_norito().map_err(|error| {
        norito_decode_attempt_error(error, |error| {
            Error::InvariantViolation(
                format!("malformed Kaigi relay registration in domain {domain_id}: {error}").into(),
            )
        })
    })?;
    let expected_key = kaigi_relay_metadata_key(&registration.relay_id).map_err(|err| {
        Error::InvariantViolation(
            format!("invalid stored Kaigi relay registration identity: {err}").into(),
        )
    })?;
    if key != &expected_key {
        return Err(Error::InvariantViolation(
            "stored Kaigi relay registration key does not match its relay ID; identifier does not match metadata key".into(),
        ).into());
    }
    validate_relay_hpke_public_key(&registration.hpke_public_key).map_err(|error| {
        Error::InvariantViolation(
            format!("stored Kaigi relay registration has an invalid HPKE key: {error}").into(),
        )
    })?;
    if registration.bandwidth_class == 0 {
        return Err(Error::InvariantViolation(
            "stored Kaigi relay registration has an invalid zero bandwidth class".into(),
        )
        .into());
    }
    Ok(registration)
}
fn decode_stored_relay_feedback(
    domain_id: &DomainId,
    key: &Name,
    value: &Json,
) -> Result<KaigiRelayFeedback, ExecutionAttemptError<Error>> {
    ensure_kaigi_json_size(
        value,
        KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1,
        "stored Kaigi relay feedback",
    )
    .map_err(|message| Error::InvariantViolation(message.into()))?;
    let feedback: KaigiRelayFeedback = value.try_into_any_norito().map_err(|error| {
        norito_decode_attempt_error(error, |error| {
            Error::InvariantViolation(
                format!("malformed Kaigi relay feedback in domain {domain_id}: {error}").into(),
            )
        })
    })?;
    let expected_key = kaigi_relay_feedback_key(&feedback.relay_id).map_err(|err| {
        Error::InvariantViolation(
            format!("invalid retained Kaigi relay feedback identity: {err}").into(),
        )
    })?;
    if &expected_key != key {
        return Err(Error::InvariantViolation(
            "retained Kaigi relay feedback key does not match its relay ID; feedback identifier does not match metadata key"
                .into(),
        ).into());
    }
    if feedback
        .notes
        .as_deref()
        .is_some_and(|notes| notes.chars().count() > KAIGI_RELAY_HEALTH_NOTES_MAX_CHARS_V1)
    {
        return Err(Error::InvariantViolation(
            format!(
                "stored Kaigi relay feedback notes exceed the {KAIGI_RELAY_HEALTH_NOTES_MAX_CHARS_V1}-character limit"
            )
            .into(),
        ).into());
    }
    Ok(feedback)
}
fn collect_kaigi_relay_registry(
    world: &impl WorldReadOnly,
) -> Result<BTreeMap<AccountId, DomainId>, ExecutionAttemptError<Error>> {
    collect_kaigi_relay_registry_from_domains(world.domains_iter())
}
fn collect_kaigi_relay_registry_from_domains<D>(
    domains: impl IntoIterator<Item = D>,
) -> Result<BTreeMap<AccountId, DomainId>, ExecutionAttemptError<Error>>
where
    D: Borrow<Domain>,
{
    collect_kaigi_relay_registry_from_domains_with(domains, |_| {})
}
fn collect_kaigi_relay_registry_from_domains_with<D>(
    domains: impl IntoIterator<Item = D>,
    mut on_registration: impl FnMut(&KaigiRelayRegistration),
) -> Result<BTreeMap<AccountId, DomainId>, ExecutionAttemptError<Error>>
where
    D: Borrow<Domain>,
{
    let mut rebuilt = BTreeMap::new();
    for domain in domains {
        let domain = domain.borrow();
        if let Some((_, value)) = domain
            .metadata()
            .iter()
            .find(|(key, _)| key.as_ref() == "kaigi_relay_allowlist")
        {
            decode_stored_kaigi_relay_allowlist(domain.id(), value)?;
        }
        for (key, value) in domain.metadata().iter() {
            if !key.as_ref().starts_with("kaigi_relay__") {
                continue;
            }
            let registration = decode_stored_relay_registration(domain.id(), key, value)?;
            if rebuilt.contains_key(&registration.relay_id) {
                return Err(Error::InvariantViolation(
                    "duplicate Kaigi relay registration found across domains".into(),
                )
                .into());
            }
            if rebuilt.len() >= KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1 {
                return Err(privacy_error(
                    "retained Kaigi relay registry exceeds the final V1 capacity",
                )
                .into());
            }
            rebuilt.insert(registration.relay_id.clone(), domain.id().clone());
            on_registration(&registration);
        }
    }
    Ok(rebuilt)
}

fn collect_kaigi_account_dependencies_at(
    world: &impl WorldReadOnly,
    max_retained_timestamp_ms: Option<u64>,
) -> Result<
    BTreeMap<AccountId, BTreeSet<KaigiAccountDependencyLocator>>,
    ExecutionAttemptError<Error>,
> {
    collect_kaigi_account_dependencies_from_domains(world.domains_iter(), max_retained_timestamp_ms)
}

fn collect_kaigi_account_dependencies_from_domains<D>(
    domains: impl IntoIterator<Item = D>,
    max_retained_timestamp_ms: Option<u64>,
) -> Result<
    BTreeMap<AccountId, BTreeSet<KaigiAccountDependencyLocator>>,
    ExecutionAttemptError<Error>,
>
where
    D: Borrow<Domain>,
{
    let mut domains = domains.into_iter().collect::<Vec<_>>();
    domains.sort_unstable_by(|left, right| {
        <D as Borrow<Domain>>::borrow(left)
            .id()
            .cmp(<D as Borrow<Domain>>::borrow(right).id())
    });
    let mut relay_keys = BTreeMap::<AccountId, Vec<u8>>::new();
    let relay_registry = collect_kaigi_relay_registry_from_domains_with(
        domains
            .iter()
            .map(|domain| <D as Borrow<Domain>>::borrow(domain)),
        |registration| {
            relay_keys.insert(
                registration.relay_id.clone(),
                registration.hpke_public_key.clone(),
            );
        },
    )?;
    let mut feedback_relays = BTreeSet::new();
    let mut rebuilt = BTreeMap::<AccountId, BTreeSet<KaigiAccountDependencyLocator>>::new();
    for domain in &domains {
        let domain = <D as Borrow<Domain>>::borrow(domain);
        for (key, value) in domain.metadata().iter() {
            let literal = key.as_ref();
            let (kind, accounts) = if literal.starts_with("kaigi__") {
                let record = decode_stored_kaigi_record(domain.id(), key, value)?;
                if record.status == KaigiStatus::Active {
                    if let Some(manifest) = record.relay_manifest.as_ref() {
                        for hop in &manifest.hops {
                            match relay_keys.get(&hop.relay_id) {
                                None => {
                                    return Err(Error::InvariantViolation(
                                        format!(
                                            "active Kaigi {} manifest relay {} has no registered descriptor at restore",
                                            record.id, hop.relay_id
                                        )
                                        .into(),
                                    ).into());
                                }
                                Some(registered_key) if registered_key != &hop.hpke_public_key => {
                                    return Err(Error::InvariantViolation(
                                        format!(
                                            "active Kaigi {} manifest relay {} HPKE key differs from its registered descriptor at restore",
                                            record.id, hop.relay_id
                                        )
                                        .into(),
                                    ).into());
                                }
                                Some(_) => {}
                            }
                        }
                    }
                }
                if let Some(maximum) = max_retained_timestamp_ms {
                    if record.created_at_ms > maximum {
                        return Err(Error::InvariantViolation(
                            format!(
                                "retained Kaigi creation timestamp {} exceeds restored ledger time {maximum}",
                                record.created_at_ms
                            )
                            .into(),
                        ).into());
                    }
                    if let Some(ended_at_ms) = record.ended_at_ms
                        && ended_at_ms > maximum
                    {
                        return Err(Error::InvariantViolation(
                            format!(
                                "retained Kaigi end timestamp {ended_at_ms} exceeds restored ledger time {maximum}"
                            )
                            .into(),
                        ).into());
                    }
                }
                (
                    KAIGI_DEPENDENCY_ACTIVE_CALL,
                    active_call_dependency_accounts(&record),
                )
            } else if literal.starts_with("kaigi_relay_feedback__") {
                let feedback = decode_stored_relay_feedback(domain.id(), key, value)?;
                match relay_registry.get(&feedback.relay_id) {
                    Some(home) if home == domain.id() => {}
                    Some(home) => {
                        return Err(Error::InvariantViolation(
                            format!(
                                "retained Kaigi relay feedback for {} is stored in domain {} instead of its registered home {home}",
                                feedback.relay_id,
                                domain.id()
                            )
                            .into(),
                        ).into());
                    }
                    None => {
                        return Err(Error::InvariantViolation(
                            format!(
                                "retained Kaigi relay feedback for {} has no registered relay descriptor",
                                feedback.relay_id
                            )
                            .into(),
                        ).into());
                    }
                }
                if !feedback_relays.insert(feedback.relay_id.clone()) {
                    return Err(Error::InvariantViolation(
                        "duplicate Kaigi relay feedback found across domains".into(),
                    )
                    .into());
                }
                if let Some(maximum) = max_retained_timestamp_ms
                    && feedback.reported_at_ms > maximum
                {
                    return Err(Error::InvariantViolation(
                        format!(
                            "retained Kaigi relay feedback timestamp {} exceeds restored ledger time {maximum}",
                            feedback.reported_at_ms
                        )
                        .into(),
                    ).into());
                }
                let call_domain = domains
                    .binary_search_by(|candidate| {
                        <D as Borrow<Domain>>::borrow(candidate)
                            .id()
                            .cmp(&feedback.call.domain_id)
                    })
                    .ok()
                    .map(|index| <D as Borrow<Domain>>::borrow(&domains[index]))
                    .ok_or_else(|| {
                        Error::InvariantViolation(
                            format!(
                                "retained Kaigi relay feedback references missing call {}",
                                feedback.call
                            )
                            .into(),
                        )
                    })?;
                let call_key = metadata_key(&feedback.call).map_err(|error| {
                    Error::InvariantViolation(
                        format!("invalid retained Kaigi relay feedback call identity: {error}")
                            .into(),
                    )
                })?;
                let call_value = call_domain.metadata().get(&call_key).ok_or_else(|| {
                    Error::InvariantViolation(
                        format!(
                            "retained Kaigi relay feedback references missing call {}",
                            feedback.call
                        )
                        .into(),
                    )
                })?;
                let call = decode_stored_kaigi_record(call_domain.id(), &call_key, call_value)?;
                if feedback.reported_at_ms < call.created_at_ms {
                    return Err(Error::InvariantViolation(
                        format!(
                            "retained Kaigi relay feedback for {} predates its creation",
                            feedback.call
                        )
                        .into(),
                    )
                    .into());
                }
                if call
                    .ended_at_ms
                    .is_some_and(|ended_at_ms| feedback.reported_at_ms > ended_at_ms)
                {
                    return Err(Error::InvariantViolation(
                        format!(
                            "retained Kaigi relay feedback for {} is later than its finalized end",
                            feedback.call
                        )
                        .into(),
                    )
                    .into());
                }
                (
                    KAIGI_DEPENDENCY_RELAY_FEEDBACK,
                    BTreeSet::from([feedback.relay_id]),
                )
            } else if literal.starts_with("kaigi_relay__") {
                let registration = decode_stored_relay_registration(domain.id(), key, value)?;
                (
                    KAIGI_DEPENDENCY_RELAY_REGISTRATION,
                    BTreeSet::from([registration.relay_id]),
                )
            } else {
                continue;
            };
            let dependency = (kind, domain.id().clone(), key.clone());
            for account in accounts {
                rebuilt
                    .entry(account)
                    .or_default()
                    .insert(dependency.clone());
            }
        }
    }
    Ok(rebuilt)
}

/// Rebuild the skipped Kaigi account-dependency reverse index from domain metadata.
pub(crate) fn rebuild_kaigi_account_dependencies(
    world: &mut World,
) -> Result<(), ExecutionAttemptError<String>> {
    rebuild_kaigi_account_dependencies_at(world, None)
}

/// Rebuild Kaigi account dependencies while bounding retained timestamps by restored ledger time.
pub(crate) fn rebuild_kaigi_account_dependencies_at(
    world: &mut World,
    max_retained_timestamp_ms: Option<u64>,
) -> Result<(), ExecutionAttemptError<String>> {
    let current = collect_kaigi_account_dependencies_at(&world.view(), max_retained_timestamp_ms)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?;
    let previous = {
        let reverted_domains = world.domains.block_and_revert();
        let rebuilt = collect_kaigi_account_dependencies_from_domains(
            reverted_domains.iter().map(|(_, domain)| domain),
            max_retained_timestamp_ms,
        )
        .map_err(|error| error.map_rejection(|error| error.to_string()))?;
        // Abort the temporary revert view so authoritative metadata and its undo journal remain
        // unchanged while the skipped index reconstructs the same two MV layers.
        drop(reverted_domains);
        rebuilt
    };
    world.kaigi_account_dependencies =
        crate::state::rebuild_derived_storage_with_previous(current, previous);
    Ok(())
}

/// Validate rebuilt Kaigi dependencies while bounding retained timestamps by restored ledger time.
pub(crate) fn validate_rebuilt_kaigi_account_dependencies_at(
    world: &impl WorldReadOnly,
    max_retained_timestamp_ms: Option<u64>,
) -> Result<(), ExecutionAttemptError<String>> {
    let expected = collect_kaigi_account_dependencies_at(world, max_retained_timestamp_ms)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?;
    let actual = world
        .kaigi_account_dependencies()
        .iter()
        .map(|(account, dependencies)| (account.clone(), dependencies.clone()))
        .collect::<BTreeMap<_, _>>();
    if actual != expected {
        return Err("Kaigi account-dependency index disagrees with authoritative metadata".into());
    }
    for domain in world.domains_iter() {
        for (key, value) in domain
            .metadata()
            .iter()
            .filter(|(key, _)| key.as_ref().starts_with("kaigi__"))
        {
            let record = decode_stored_kaigi_record(domain.id(), key, value)
                .map_err(|error| error.map_rejection(|error| error.to_string()))?;
            validate_private_participation_lineages(world, &record)
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn validate_private_participation_lineages(
    world: &impl WorldReadOnly,
    record: &KaigiRecord,
) -> Result<(), Error> {
    if record.status != KaigiStatus::Active || record.privacy_mode != KaigiPrivacyMode::ZkRosterV1 {
        return Ok(());
    }
    let mut endpoints = BTreeSet::new();
    for owner in std::iter::once(&record.host).chain(
        record
            .private_participation
            .entries()
            .iter()
            .map(|entry| entry.original_account()),
    ) {
        // Independent components get independent work bounds. Combining all
        // participants here would reject valid calls after unrelated rekeys.
        let graph = persisted_kaigi_rekey_graph(world, [owner.clone()])?;
        let endpoint =
            resolve_persisted_kaigi_rekey_successor(world, owner, &graph)?.ok_or_else(|| {
                privacy_error("active private Kaigi owner has no registered successor")
            })?;
        if !endpoints.insert(endpoint) {
            return Err(privacy_error(
                "private Kaigi host or retained subjects share one rekey lineage",
            ));
        }
    }
    Ok(())
}

/// Rebuild the derived relay-to-domain index from authoritative domain metadata.
///
/// Restored registry membership must satisfy the same final V1 bounds as admission.
///
/// # Errors
///
/// Returns the original local decode deferral, or a completed rejection when an
/// authoritative relay row is malformed or duplicated.
pub(crate) fn rebuild_kaigi_relay_registry(
    world: &mut World,
) -> Result<(), ExecutionAttemptError<String>> {
    let current = collect_kaigi_relay_registry(&world.view())
        .map_err(|error| error.map_rejection(|error| error.to_string()))?;
    let previous = {
        let reverted_domains = world.domains.block_and_revert();
        let rebuilt = collect_kaigi_relay_registry_from_domains(
            reverted_domains.iter().map(|(_, domain)| domain),
        )
        .map_err(|error| error.map_rejection(|error| error.to_string()))?;
        // Abort the temporary revert view so authoritative domain metadata and its undo journal
        // remain unchanged while the skipped relay index reconstructs the same two MV layers.
        drop(reverted_domains);
        rebuilt
    };
    world.kaigi_relay_registry =
        crate::state::rebuild_derived_storage_with_previous(current, previous);
    Ok(())
}
/// Validate rebuilt relay membership against persisted account lineage and home domains.
///
/// # Errors
///
/// Returns the original local decode deferral, or a completed rejection when the
/// index disagrees with authoritative metadata or relay lineage.
pub(crate) fn validate_rebuilt_kaigi_relay_registry(
    world: &impl WorldReadOnly,
) -> Result<(), ExecutionAttemptError<String>> {
    let graph = persisted_kaigi_rekey_graph(
        world,
        world
            .kaigi_relay_registry()
            .iter()
            .map(|(relay_id, _)| relay_id.clone()),
    )
    .map_err(|error| error.to_string())?;
    for (relay_id, domain_id) in world.kaigi_relay_registry().iter() {
        let key = kaigi_relay_metadata_key(relay_id).map_err(|error| error.to_string())?;
        let value = world
            .domain(domain_id)
            .map_err(|error| error.to_string())?
            .metadata()
            .get(&key)
            .ok_or_else(|| {
                format!(
                    "Kaigi relay registry entry for {relay_id} is missing authoritative metadata"
                )
            })?;
        let registration = decode_stored_relay_registration(domain_id, &key, value)
            .map_err(|error| error.map_rejection(|error| error.to_string()))?;
        if &registration.relay_id != relay_id {
            return Err(format!(
                "Kaigi relay registry key {relay_id} does not match its metadata registration"
            )
            .into());
        }
        let resolved_domain =
            persisted_relay_domain(world, relay_id, &graph).map_err(|error| error.to_string())?;
        if &resolved_domain != domain_id {
            return Err(format!(
                "Kaigi relay {relay_id} is stored in {domain_id}, outside its persisted home domain {resolved_domain}"
            ).into());
        }
    }
    Ok(())
}
#[cfg(test)]
fn validated_kaigi_relay_registry_count(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<usize, Error> {
    let graph = persisted_kaigi_rekey_graph(
        &state_transaction.world,
        state_transaction
            .world
            .kaigi_relay_registry
            .iter()
            .map(|(relay_id, _)| relay_id.clone()),
    )?;
    validated_kaigi_relay_registry_count_with_graph(state_transaction, &graph)
}
#[cfg(test)]
fn validated_kaigi_relay_registry_count_with_graph(
    state_transaction: &StateTransaction<'_, '_>,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<usize, Error> {
    let mut count = 0usize;
    for (relay_id, domain_id) in state_transaction.world.kaigi_relay_registry.iter() {
        let key = kaigi_relay_metadata_key(relay_id).map_err(|err| {
            Error::InvariantViolation(
                format!("invalid indexed Kaigi relay registration identity: {err}").into(),
            )
        })?;
        let value = state_transaction
            .world
            .domain(domain_id)?
            .metadata()
            .get(&key)
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "Kaigi relay registry entry is missing authoritative metadata".into(),
                )
            })?;
        let registration =
            decode_stored_relay_registration(domain_id, &key, value).map_err(|error| {
                state_transaction
                    .world
                    .attempt_error_to_instruction_error(error)
            })?;
        if &registration.relay_id != relay_id {
            return Err(Error::InvariantViolation(
                "Kaigi relay registry key does not match its metadata registration".into(),
            ));
        }
        let resolved_domain =
            relay_domain_from_persisted_graph(state_transaction, relay_id, graph)?;
        if &resolved_domain != domain_id {
            return Err(Error::InvariantViolation(
                "stored Kaigi relay registration is outside its relay's persisted home domain"
                    .into(),
            ));
        }
        count = count.saturating_add(1);
        if count > KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1 {
            return Ok(count);
        }
    }
    Ok(count)
}
fn ensure_manifest_relays_registered(
    state_transaction: &StateTransaction<'_, '_>,
    manifest: &KaigiRelayManifest,
) -> Result<(), Error> {
    if manifest.expiry_ms <= state_transaction.block_unix_timestamp_ms() {
        return Err(relay_error(
            "relay manifest expiry must be greater than the current block time",
        ));
    }
    let rekey_graph = persisted_kaigi_rekey_graph(
        &state_transaction.world,
        manifest.hops.iter().map(|hop| hop.relay_id.clone()),
    )?;
    let mut active_relays = BTreeSet::new();
    for hop in &manifest.hops {
        let active_relay = resolve_active_kaigi_account_with_graph(
            state_transaction,
            &hop.relay_id,
            &rekey_graph,
        )?
        .ok_or_else(|| relay_error("relay manifest references an unregistered relay account"))?;
        if !active_relays.insert(active_relay) {
            return Err(relay_error(
                "relay manifest must not contain multiple identities from the same active account-id rekey lineage",
            ));
        }
    }
    let mut allowlists = BTreeMap::<DomainId, Option<KaigiRelayAllowlist>>::new();
    for hop in &manifest.hops {
        let key = kaigi_relay_metadata_key(&hop.relay_id).map_err(|err| {
            Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
        })?;
        let domain_id = relay_domain_with_graph(state_transaction, &hop.relay_id, &rekey_graph)?;
        if !allowlists.contains_key(&domain_id) {
            let allowlist = load_allowlist(state_transaction, &domain_id)?;
            allowlists.insert(domain_id.clone(), allowlist);
        }
        ensure_relay_allowed_by_loaded_allowlist(
            state_transaction,
            &hop.relay_id,
            &rekey_graph,
            allowlists.get(&domain_id).and_then(Option::as_ref),
        )?;
        let domain = state_transaction.world.domain(&domain_id)?;
        let stored = domain.metadata().get(&key).ok_or_else(|| {
            relay_error("relay referenced in manifest is not registered in its domain")
        })?;
        let registration = decode_stored_relay_registration(&domain_id, &key, stored)
            .map_err(|error| error.map_rejection(|error| relay_error(error.to_string())))
            .map_err(|error| {
                state_transaction
                    .world
                    .attempt_error_to_instruction_error(error)
            })?;
        if registration.relay_id != hop.relay_id {
            return Err(relay_error(
                "stored relay registration identifier does not match its metadata key",
            ));
        }
        if registration.bandwidth_class == 0 {
            return Err(relay_error(
                "stored relay registration has an invalid zero bandwidth class",
            ));
        }
        if registration.hpke_public_key != hop.hpke_public_key {
            return Err(relay_error(
                "relay HPKE public key does not match registered value",
            ));
        }
    }
    Ok(())
}
fn ensure_relay_allowed_by_governance_with_graph(
    state_transaction: &StateTransaction<'_, '_>,
    relay_id: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<(), Error> {
    let domain_id = relay_domain_with_graph(state_transaction, relay_id, graph)?;
    let allowlist = load_allowlist(state_transaction, &domain_id)?;
    ensure_relay_allowed_by_loaded_allowlist(state_transaction, relay_id, graph, allowlist.as_ref())
}
fn ensure_relay_allowed_by_loaded_allowlist(
    state_transaction: &StateTransaction<'_, '_>,
    relay_id: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
    allowlist: Option<&KaigiRelayAllowlist>,
) -> Result<(), Error> {
    let Some(allowlist) = allowlist else {
        return Ok(());
    };
    let relay_component = persisted_kaigi_rekey_component(&graph.neighbours, relay_id);
    let matched = relay_component
        .iter()
        .find(|identity| allowlist.allowed_relays.contains(*identity));
    let Some(matched) = matched else {
        return Err(relay_error(
            "relay is not present in the governance allowlist for its domain",
        ));
    };
    if !accounts_share_active_lineage_with_graph(state_transaction, matched, relay_id, graph)? {
        return Err(Error::InvariantViolation(
            "allowlisted Kaigi relay identity does not resolve to the requested active lineage"
                .into(),
        ));
    }
    Ok(())
}
fn decode_kaigi_relay_allowlist(
    value: &Json,
) -> Result<KaigiRelayAllowlist, ExecutionAttemptError<String>> {
    ensure_kaigi_json_size(
        value,
        KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1,
        "Kaigi relay allowlist",
    )?;
    let allowlist: KaigiRelayAllowlist = value.try_into_any_norito().map_err(|error| {
        norito_decode_attempt_error(error, |error| {
            format!("malformed Kaigi relay allowlist: {error}")
        })
    })?;
    if allowlist.allowed_relays.len() > KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1 {
        return Err(format!(
            "Kaigi relay allowlist exceeds the {KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1}-entry limit"
        )
        .into());
    }
    Ok(allowlist)
}
fn decode_stored_kaigi_relay_allowlist(
    domain_id: &DomainId,
    value: &Json,
) -> Result<KaigiRelayAllowlist, ExecutionAttemptError<Error>> {
    decode_kaigi_relay_allowlist(value).map_err(|error| {
        error.map_rejection(|message| {
            Error::InvariantViolation(
                format!("invalid retained Kaigi relay allowlist in domain {domain_id}: {message}")
                    .into(),
            )
        })
    })
}
/// Validate a governance write to the exact Kaigi relay-allowlist metadata key.
///
/// Original codec refusal remains deferred; malformed values and V1 bounds are
/// completed rejection. The caller installs the sticky World publication guard.
pub(crate) fn validate_kaigi_relay_allowlist_metadata(
    key: &Name,
    value: &Json,
) -> Result<(), ExecutionAttemptError<Error>> {
    if key.as_ref() != "kaigi_relay_allowlist" {
        return Ok(());
    }
    decode_kaigi_relay_allowlist(value)
        .map(|_| ())
        .map_err(|error| {
            error.map_rejection(|message| {
                Error::InvalidParameter(InvalidParameterError::SmartContract(message))
            })
        })
}
fn load_allowlist(
    state_transaction: &StateTransaction<'_, '_>,
    domain_id: &DomainId,
) -> Result<Option<KaigiRelayAllowlist>, Error> {
    let key = kaigi_relay_allowlist_key().map_err(|err| {
        Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
    })?;
    let domain = state_transaction.world.domain(domain_id)?;
    let Some(stored) = domain.metadata().get(&key) else {
        return Ok(None);
    };
    let allowlist = decode_stored_kaigi_relay_allowlist(domain_id, stored).map_err(|error| {
        state_transaction
            .world
            .attempt_error_to_instruction_error(error)
    })?;
    Ok(Some(allowlist))
}
fn load_relay_feedback(
    state_transaction: &StateTransaction<'_, '_>,
    relay_id: &AccountId,
) -> Result<Option<KaigiRelayFeedback>, Error> {
    let key = kaigi_relay_feedback_key(relay_id).map_err(|err| {
        Error::InvalidParameter(InvalidParameterError::SmartContract(err.to_string()))
    })?;
    let domain_id = relay_domain(state_transaction, relay_id)?;
    let domain = state_transaction.world.domain(&domain_id)?;
    let Some(stored) = domain.metadata().get(&key) else {
        return Ok(None);
    };
    let feedback = decode_stored_relay_feedback(&domain_id, &key, stored).map_err(|error| {
        state_transaction
            .world
            .attempt_error_to_instruction_error(error)
    })?;
    if feedback.relay_id != *relay_id {
        return Err(Error::InvariantViolation(
            "stored Kaigi relay feedback identifier does not match metadata key".into(),
        ));
    }
    Ok(Some(feedback))
}
fn truncate_len(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}
fn emit_roster_summary(stx: &mut StateTransaction<'_, '_>, record: &KaigiRecord) {
    let summary = KaigiRosterSummary {
        call: record.id.clone(),
        privacy_mode: record.privacy_mode,
        participant_count: truncate_len(record.participants.len()),
        commitment_count: truncate_len(record.roster_commitments.len()),
        nullifier_count: truncate_len(record.nullifier_log.len()),
        roster_root: match record.privacy_mode {
            KaigiPrivacyMode::ZkRosterV1 => Some(record.roster_root()),
            KaigiPrivacyMode::Transparent => None,
        },
    };
    stx.world
        .emit_events(Some(DomainEvent::KaigiRosterSummary(summary)));
}
fn emit_relay_registration_summary(
    stx: &mut StateTransaction<'_, '_>,
    domain_id: &DomainId,
    registration: &KaigiRelayRegistration,
) {
    let fingerprint = Hash::new(&registration.hpke_public_key);
    let summary = KaigiRelayRegistrationSummary::new(
        domain_id.clone(),
        registration.relay_id.clone(),
        registration.bandwidth_class,
        fingerprint,
    );
    stx.world
        .emit_events(Some(DomainEvent::KaigiRelayRegistered(summary)));
}
fn emit_relay_unregistration_summary(
    stx: &mut StateTransaction<'_, '_>,
    domain_id: &DomainId,
    relay_id: &AccountId,
) {
    let summary = KaigiRelayUnregistrationSummary::new(domain_id.clone(), relay_id.clone());
    stx.world
        .emit_events(Some(DomainEvent::KaigiRelayUnregistered(summary)));
}
fn relay_domain(
    state_transaction: &StateTransaction<'_, '_>,
    relay_id: &AccountId,
) -> Result<DomainId, Error> {
    let graph = persisted_kaigi_rekey_graph(&state_transaction.world, [relay_id.clone()])?;
    relay_domain_with_graph(state_transaction, relay_id, &graph)
}
fn relay_domain_with_graph(
    state_transaction: &StateTransaction<'_, '_>,
    relay_id: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<DomainId, Error> {
    let relay_subject =
        resolve_active_kaigi_account_with_graph(state_transaction, relay_id, graph)?.ok_or_else(
            || relay_error("relay account is not registered or in an active rekey lineage"),
        )?;
    active_relay_subject_domain(state_transaction, &relay_subject)
}
fn relay_domain_from_persisted_graph(
    state_transaction: &StateTransaction<'_, '_>,
    relay_id: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<DomainId, Error> {
    let relay_subject =
        resolve_persisted_kaigi_rekey_successor(&state_transaction.world, relay_id, graph)?
            .ok_or_else(|| {
                relay_error("relay account is not registered or in a persisted lineage")
            })?;
    relay_subject_domain(&state_transaction.world, &relay_subject)
}
fn active_relay_subject_domain(
    state_transaction: &StateTransaction<'_, '_>,
    relay_subject: &AccountId,
) -> Result<DomainId, Error> {
    let primary_alias = state_transaction
        .world
        .account(relay_subject)?
        .label()
        .cloned()
        .ok_or_else(|| {
            relay_error("relay account requires an active domain-qualified primary alias")
        })?;
    let resolved = crate::sns::resolve_active_account_alias(
        &state_transaction.world,
        state_transaction.world.dataspace_catalog(),
        &primary_alias,
        state_transaction.block_unix_timestamp_ms(),
    )
    .map_err(|error| {
        state_transaction
            .world
            .attempt_error_to_instruction_error(error.into_attempt_error(|error| {
                Error::InvariantViolation(
                    format!(
                        "failed to resolve relay primary account alias `{primary_alias:?}`: {error}"
                    )
                    .into(),
                )
            }))
    })?;
    if resolved.as_ref() != Some(relay_subject) {
        return Err(relay_error(
            "relay account requires an active domain-qualified primary alias",
        ));
    }
    relay_subject_domain(&state_transaction.world, relay_subject)
}
fn relay_subject_domain(
    world: &impl WorldReadOnly,
    relay_subject: &AccountId,
) -> Result<DomainId, Error> {
    let primary_alias = world
        .account(relay_subject)?
        .label()
        .cloned()
        .ok_or_else(|| {
            relay_error("relay account requires an active domain-qualified primary alias")
        })?;
    let domain_id = primary_alias
        .domain_id(world.dataspace_catalog())
        .map_err(|err| {
            Error::InvariantViolation(
                format!("failed to resolve relay primary alias domain `{primary_alias:?}`: {err}")
                    .into(),
            )
        })?
        .ok_or_else(|| {
            relay_error("relay account requires an active domain-qualified primary alias")
        })?;
    world.domain(&domain_id)?;
    Ok(domain_id)
}
fn persisted_relay_domain(
    world: &impl WorldReadOnly,
    relay_id: &AccountId,
    graph: &PersistedKaigiRekeyGraph,
) -> Result<DomainId, Error> {
    let relay_subject = resolve_persisted_kaigi_rekey_successor(world, relay_id, graph)?
        .ok_or_else(|| relay_error("relay account is not registered or in a persisted lineage"))?;
    relay_subject_domain(world, &relay_subject)
}
fn emit_relay_manifest_summary(
    stx: &mut StateTransaction<'_, '_>,
    call_id: &KaigiId,
    manifest: Option<&KaigiRelayManifest>,
) {
    let (hop_count, expiry_ms) = manifest.map_or((0, 0), |manifest| {
        (truncate_len(manifest.hops.len()), manifest.expiry_ms)
    });
    let summary = KaigiRelayManifestSummary {
        call: call_id.clone(),
        hop_count,
        expiry_ms,
    };
    stx.world
        .emit_events(Some(DomainEvent::KaigiRelayManifestUpdated(summary)));
}
fn emit_status_summary(stx: &mut StateTransaction<'_, '_>, record: &KaigiRecord) {
    let summary = KaigiStatusSummary::new(record.id.clone(), record.status, record.ended_at_ms);
    stx.world
        .emit_events(Some(DomainEvent::KaigiStatusChanged(summary)));
}
fn emit_usage_summary(stx: &mut StateTransaction<'_, '_>, record: &KaigiRecord) {
    let summary = KaigiUsageSummary {
        call: record.id.clone(),
        total_duration_ms: record.total_duration_ms,
        total_billed_gas: record.total_billed_gas,
        segments_recorded: truncate_len(record.segments_recorded as usize),
    };
    stx.world
        .emit_events(Some(DomainEvent::KaigiUsageSummary(summary)));
}
fn emit_relay_health_summary(
    stx: &mut StateTransaction<'_, '_>,
    relay_domain: &DomainId,
    feedback: &KaigiRelayFeedback,
) {
    let summary = KaigiRelayHealthSummary::new(
        relay_domain.clone(),
        feedback.call.clone(),
        feedback.relay_id.clone(),
        feedback.status,
        feedback.reported_at_ms,
    );
    stx.world
        .emit_events(Some(DomainEvent::KaigiRelayHealthUpdated(summary)));
}
#[allow(clippy::too_many_arguments)]
fn process_join(
    state_transaction: &mut StateTransaction<'_, '_>,
    record: &mut KaigiRecord,
    authorization: KaigiAuthorization<'_>,
    participant: &AccountId,
    mut commitment: Option<KaigiParticipantCommitment>,
    mut nullifier: Option<KaigiParticipantNullifier>,
    roster_root: Option<iroha_crypto::Hash>,
    proof: Option<&[u8]>,
) -> Result<AccessGrant, Error> {
    ensure_kaigi_active(record)?;
    let authority = authorization.signed_account();
    match record.privacy_mode {
        KaigiPrivacyMode::Transparent => {
            let rekey_graph = persisted_kaigi_rekey_graph(
                &state_transaction.world,
                [record.host.clone(), participant.clone(), authority.clone()],
            )?;
            if accounts_share_active_lineage_with_graph(
                state_transaction,
                &record.host,
                participant,
                &rekey_graph,
            )? {
                return Err(Error::InvalidParameter(
                    InvalidParameterError::SmartContract("host is already part of the call".into()),
                ));
            }
            privacy::ensure_transparent_payload(&PrivacyArtifacts {
                commitment: commitment.as_ref(),
                nullifier: nullifier.as_ref(),
                roster_root: roster_root.as_ref(),
                proof,
            })?;
            if authority != participant
                && !accounts_share_active_lineage_with_graph(
                    state_transaction,
                    authority,
                    &record.host,
                    &rekey_graph,
                )?
            {
                return Err(unauthorized("only the host may invite other accounts"));
            }
            if record_has_participant_in_active_lineage(
                state_transaction,
                record,
                participant,
                &rekey_graph,
            )? {
                return Err(Error::InvariantViolation(
                    "participant already joined".into(),
                ));
            }
            let participant_limit = record
                .max_participants
                .map_or(KAIGI_MAX_PARTICIPANTS_V1, |limit| {
                    usize::try_from(limit).unwrap_or(usize::MAX)
                });
            if record.participants.len() >= participant_limit {
                return Err(Error::InvalidParameter(
                    InvalidParameterError::SmartContract("participant limit reached".into()),
                ));
            }
            record.push_participant(participant.clone());
            Ok(AccessGrant::Default)
        }
        KaigiPrivacyMode::ZkRosterV1 => {
            let original = original_participant_v1(
                state_transaction,
                &record.private_participation,
                &record.host,
                authority,
                participant,
                KaigiAuthorizationActionV1::Join,
            )?;
            let sequence = record
                .private_participation
                .prepare_join(&original)
                .map_err(|error| privacy_error(error.to_string()))?;
            let commitment = commitment
                .take()
                .ok_or_else(|| privacy_error("privacy mode requires commitment"))?;
            let nullifier = nullifier
                .take()
                .ok_or_else(|| privacy_error("privacy mode requires nullifier"))?;
            if record.has_commitment(&commitment) {
                return Err(privacy_error("commitment already registered"));
            }
            if record.has_nullifier(&nullifier) {
                return Err(privacy_error("nullifier already used"));
            }
            let participant_limit = record
                .max_participants
                .map_or(KAIGI_MAX_PARTICIPANTS_V1, |limit| {
                    usize::try_from(limit).unwrap_or(usize::MAX)
                });
            if record.roster_commitments.len() >= participant_limit {
                return Err(privacy_error("participant limit reached"));
            }
            ensure_action_capacity_v1(
                record.nullifier_log.len(),
                record.roster_commitments.len(),
                KaigiAuthorizationActionV1::Join,
            )?;
            let context = context_from_ledger_v1(
                *state_transaction.network_id(),
                &record.id,
                &record.host,
                &original,
                sequence,
                KaigiAuthorizationActionV1::Join,
                &record.roster_root(),
            )?;
            privacy::verify_authorization(
                state_transaction,
                &PrivacyArtifacts {
                    commitment: Some(&commitment),
                    nullifier: Some(&nullifier),
                    roster_root: roster_root.as_ref(),
                    proof,
                },
                &context,
                None,
            )?;
            record
                .private_participation
                .commit_join(&original, sequence, commitment.commitment)
                .map_err(|error| privacy_error(error.to_string()))?;
            record.push_commitment(commitment);
            record.push_nullifier(nullifier);
            Ok(AccessGrant::PrivacyAuthorized)
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn process_leave(
    state_transaction: &mut StateTransaction<'_, '_>,
    record: &mut KaigiRecord,
    authority: &AccountId,
    participant: &AccountId,
    mut commitment: Option<KaigiParticipantCommitment>,
    mut nullifier: Option<KaigiParticipantNullifier>,
    roster_root: Option<iroha_crypto::Hash>,
    proof: Option<&[u8]>,
) -> Result<AccessGrant, Error> {
    ensure_kaigi_active(record)?;
    match record.privacy_mode {
        KaigiPrivacyMode::Transparent => {
            let rekey_graph = persisted_kaigi_rekey_graph(
                &state_transaction.world,
                [record.host.clone(), participant.clone(), authority.clone()],
            )?;
            privacy::ensure_transparent_payload(&PrivacyArtifacts {
                commitment: commitment.as_ref(),
                nullifier: nullifier.as_ref(),
                roster_root: roster_root.as_ref(),
                proof,
            })?;
            if !accounts_share_active_lineage_with_graph(
                state_transaction,
                authority,
                participant,
                &rekey_graph,
            )? && !accounts_share_active_lineage_with_graph(
                state_transaction,
                authority,
                &record.host,
                &rekey_graph,
            )? {
                return Err(unauthorized(
                    "only the host or participant may remove a participant",
                ));
            }
            if accounts_share_active_lineage_with_graph(
                state_transaction,
                &record.host,
                participant,
                &rekey_graph,
            )? {
                return Err(Error::InvalidParameter(
                    InvalidParameterError::SmartContract(
                        "host cannot leave the call without ending it".into(),
                    ),
                ));
            }
            let matching_indexes = record_participant_indexes_in_active_lineage(
                state_transaction,
                record,
                participant,
                &rekey_graph,
            )?;
            if matching_indexes.len() > 1 {
                return Err(Error::InvariantViolation(
                    "multiple Kaigi participants resolve to the same active account-id rekey lineage"
                        .into(),
                ));
            }
            let matching_index = matching_indexes
                .into_iter()
                .next()
                .ok_or_else(|| Error::Find(FindError::Account(participant.clone())))?;
            let stored_participant = record.participants.remove(matching_index);
            record.participant_metadata.remove(&stored_participant);
            Ok(AccessGrant::Default)
        }
        KaigiPrivacyMode::ZkRosterV1 => {
            let original = original_participant_v1(
                state_transaction,
                &record.private_participation,
                &record.host,
                authority,
                participant,
                KaigiAuthorizationActionV1::Leave,
            )?;
            let commitment = commitment
                .take()
                .ok_or_else(|| privacy_error("privacy mode requires commitment"))?;
            let nullifier = nullifier
                .take()
                .ok_or_else(|| privacy_error("privacy mode requires nullifier"))?;
            let sequence = record
                .private_participation
                .prepare_leave(&original, commitment.commitment)
                .map_err(|error| privacy_error(error.to_string()))?;
            if !record.has_commitment(&commitment) {
                return Err(privacy_error("stored participation is absent from roster"));
            }
            if record.has_nullifier(&nullifier) {
                return Err(privacy_error("nullifier already used"));
            }
            ensure_action_capacity_v1(
                record.nullifier_log.len(),
                record.roster_commitments.len(),
                KaigiAuthorizationActionV1::Leave,
            )?;
            let context = context_from_ledger_v1(
                *state_transaction.network_id(),
                &record.id,
                &record.host,
                &original,
                sequence,
                KaigiAuthorizationActionV1::Leave,
                &record.roster_root(),
            )?;
            privacy::verify_authorization(
                state_transaction,
                &PrivacyArtifacts {
                    commitment: Some(&commitment),
                    nullifier: Some(&nullifier),
                    roster_root: roster_root.as_ref(),
                    proof,
                },
                &context,
                Some(&commitment.commitment),
            )?;
            record
                .private_participation
                .commit_leave(&original, sequence, commitment.commitment)
                .map_err(|error| privacy_error(error.to_string()))?;
            if !record.remove_commitment(&commitment) {
                return Err(privacy_error(
                    "authorized commitment disappeared from roster",
                ));
            }
            record.push_nullifier(nullifier);
            Ok(AccessGrant::PrivacyAuthorized)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::privacy::proof_fixture_v1::{AuthorizationFixtureV1, authorization_fixture_v1};
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World, WorldReadOnly},
    };
    use core::num::NonZeroU64;
    use iroha_data_model::{
        events::{
            data::prelude::{
                DataEvent, DomainEvent, KaigiRelayRegistrationSummary,
                KaigiRelayUnregistrationSummary, KaigiStatusSummary,
            },
            prelude::EventBox,
        },
        kaigi::{KaigiRelayHop, KaigiRelayManifest, KaigiRelayRegistration, NewKaigi},
        prelude::*,
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_test_samples::{ALICE_ID, gen_account_in};
    use std::str::FromStr;
    #[test]
    fn unauthorized_error_contains_message() {
        match unauthorized("test message") {
            Error::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
                assert_eq!(msg, "test message");
            }
            other => panic!("unexpected error variant {other:?}"),
        }
    }
    #[test]
    fn native_kaigi_metadata_key_reservation_excludes_governance_allowlist() {
        let (_domain, host, _) = sample_ids();
        let call_name = Name::from_str("reserved-key").expect("call name");
        for key in [
            kaigi_metadata_key(&call_name).expect("call metadata key"),
            kaigi_relay_metadata_key(&host).expect("relay metadata key"),
            kaigi_relay_feedback_key(&host).expect("relay feedback key"),
        ] {
            assert!(
                is_reserved_kaigi_metadata_key(&key),
                "native Kaigi key {key} must be protected"
            );
        }
        assert!(
            !is_reserved_kaigi_metadata_key(
                &kaigi_relay_allowlist_key().expect("allowlist metadata key")
            ),
            "domain governance must retain the ordinary allowlist update path"
        );
        let unrelated = Name::from_str("kaigi_topic").expect("unrelated metadata key");
        assert!(!is_reserved_kaigi_metadata_key(&unrelated));
    }
    #[test]
    fn kaigi_json_work_bound_checks_exact_limit_before_decode() {
        assert!(
            ensure_kaigi_json_len(
                KAIGI_RECORD_MAX_JSON_BYTES_V1,
                KAIGI_RECORD_MAX_JSON_BYTES_V1,
                "stored Kaigi call record",
            )
            .is_ok()
        );
        let error = ensure_kaigi_json_len(
            KAIGI_RECORD_MAX_JSON_BYTES_V1 + 1,
            KAIGI_RECORD_MAX_JSON_BYTES_V1,
            "stored Kaigi call record",
        )
        .expect_err("one byte over the protocol bound must fail before decode");
        assert!(error.contains("1048576-byte JSON limit"), "{error}");
    }
    #[test]
    fn kaigi_record_v1_collection_bounds_accept_exact_limit_and_reject_next() {
        let (mut record, _, _) = new_record(KaigiPrivacyMode::Transparent);
        record.max_participants =
            Some(u32::try_from(KAIGI_MAX_PARTICIPANTS_V1).expect("participant limit fits u32"));
        validate_kaigi_record_v1(&record).expect("exact participant limit is valid");
        record.max_participants = Some(
            u32::try_from(KAIGI_MAX_PARTICIPANTS_V1 + 1)
                .expect("participant limit plus one fits u32"),
        );
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("participant limit plus one must fail")
                .contains("max_participants")
        );

        let mut participant_ids = synthetic_multisig_account_ids(KAIGI_MAX_PARTICIPANTS_V1 + 1);
        participant_ids.sort_unstable();
        record.max_participants = None;
        record.participants = participant_ids[..KAIGI_MAX_PARTICIPANTS_V1].to_vec();
        validate_kaigi_record_v1(&record).expect("exact transparent roster limit is valid");
        record
            .participants
            .push(participant_ids[KAIGI_MAX_PARTICIPANTS_V1].clone());
        record.participants.sort_unstable();
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("transparent roster limit plus one must fail")
                .contains("participants exceed")
        );

        let hashes = (0..=KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1)
            .map(|index| test_scalar(u64::try_from(index).unwrap()))
            .collect::<Vec<_>>();
        let (mut private, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        private.roster_commitments = hashes[..KAIGI_MAX_PARTICIPANTS_V1]
            .iter()
            .cloned()
            .map(|commitment| KaigiParticipantCommitment { commitment })
            .collect();
        private.roster_root = KaigiRecord::compute_roster_root(&private.roster_commitments);
        for (account, commitment) in participant_ids.iter().zip(&private.roster_commitments) {
            private
                .private_participation
                .commit_join(account, 1, commitment.commitment)
                .unwrap();
        }
        validate_kaigi_record_v1(&private).expect("exact private roster limit is valid");
        private.roster_commitments.push(KaigiParticipantCommitment {
            commitment: hashes[KAIGI_MAX_PARTICIPANTS_V1].clone(),
        });
        assert!(
            validate_kaigi_record_v1(&private)
                .expect_err("private roster limit plus one must fail")
                .contains("roster commitments exceed")
        );

        let (mut private, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        private.nullifier_log = hashes[..KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1]
            .iter()
            .cloned()
            .map(|digest| KaigiParticipantNullifier { digest })
            .collect();
        private.status = KaigiStatus::Ended;
        private.ended_at_ms = Some(private.created_at_ms);
        validate_kaigi_record_v1(&private).expect("exact terminal nullifier limit is valid");
        private.nullifier_log.push(KaigiParticipantNullifier {
            digest: hashes[KAIGI_MAX_NULLIFIER_LOG_ENTRIES_V1].clone(),
        });
        assert!(
            validate_kaigi_record_v1(&private)
                .expect_err("nullifier limit plus one must fail")
                .contains("nullifier log exceeds")
        );

        let (mut private, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        private.usage_commitments = hashes[..KAIGI_MAX_USAGE_COMMITMENTS_V1].to_vec();
        private.segments_recorded =
            u32::try_from(KAIGI_MAX_USAGE_COMMITMENTS_V1).expect("usage limit fits u32");
        validate_kaigi_record_v1(&private).expect("exact usage commitment limit is valid");
        private
            .usage_commitments
            .push(hashes[KAIGI_MAX_USAGE_COMMITMENTS_V1].clone());
        private.segments_recorded = private.segments_recorded.saturating_add(1);
        assert!(
            validate_kaigi_record_v1(&private)
                .expect_err("usage commitment limit plus one must fail")
                .contains("usage commitments exceed")
        );
    }
    #[test]
    fn kaigi_record_v1_preserves_host_metadata_and_rejects_foreign_keys() {
        let (mut record, _, foreign) = new_record(KaigiPrivacyMode::Transparent);
        record
            .participant_metadata
            .insert(record.host.clone(), Metadata::default());
        validate_kaigi_record_v1(&record).expect("host metadata remains a supported record shape");
        record
            .participant_metadata
            .insert(foreign, Metadata::default());
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("metadata for an unrelated account must fail")
                .contains("host or a current participant")
        );

        let (mut private, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        private
            .participant_metadata
            .insert(private.host.clone(), Metadata::default());
        validate_kaigi_record_v1(&private)
            .expect("private records may retain metadata for their host");
    }
    #[test]
    fn kaigi_record_v1_rejects_unreachable_host_membership_and_billing() {
        let (mut record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        record.billing_account = Some(participant);
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("third-party billing cannot be restored before it is supported")
                .contains("billing account must equal the host")
        );

        record.billing_account = Some(host.clone());
        validate_kaigi_record_v1(&record).expect("an explicit host billing account remains valid");
        record.push_participant(host);
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("the implicit host must not be restored as a participant")
                .contains("participants must not include the host")
        );
    }
    #[test]
    fn kaigi_record_v1_usage_segment_invariant_is_privacy_mode_sensitive() {
        let (mut transparent, _, _) = new_record(KaigiPrivacyMode::Transparent);
        transparent.segments_recorded = 1;
        validate_kaigi_record_v1(&transparent)
            .expect("transparent usage segments do not retain commitments");

        let (mut private, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        private.segments_recorded = 1;
        assert!(
            validate_kaigi_record_v1(&private)
                .expect_err("private usage segments must retain commitments")
                .contains("segment count must match")
        );
    }
    #[test]
    fn kaigi_record_v1_enforces_roster_root_and_mode_specific_state() {
        let (mut private, _, participant) = new_record(KaigiPrivacyMode::ZkRosterV1);
        private.roster_root = Hash::new(b"incorrect retained roster root");
        assert!(
            validate_kaigi_record_v1(&private)
                .expect_err("a stale private roster root must fail")
                .contains("roster root does not match")
        );

        let (mut private, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        private.push_participant(participant);
        assert!(
            validate_kaigi_record_v1(&private)
                .expect_err("private records must not retain transparent participants")
                .contains("transparent participant IDs")
        );

        for artifact in 0..4 {
            let (mut transparent, _, _) = new_record(KaigiPrivacyMode::Transparent);
            match artifact {
                0 => transparent.host_commitment = Some(sample_commitment()),
                1 => transparent.push_commitment(sample_commitment()),
                2 => transparent.push_nullifier(sample_nullifier(0xB1)),
                3 => transparent.push_usage_commitment(test_scalar(55)),
                _ => unreachable!("bounded artifact cases"),
            }
            assert!(
                validate_kaigi_record_v1(&transparent)
                    .expect_err("transparent records must reject private artifacts")
                    .contains("must not retain private roster artifacts")
            );
        }
    }
    #[test]
    fn kaigi_record_v1_enforces_lifecycle_timestamp_shape() {
        let (mut record, _, _) = new_record(KaigiPrivacyMode::Transparent);
        record.created_at_ms = 10;
        record.ended_at_ms = Some(10);
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("an active record with an end timestamp must fail")
                .contains("active Kaigi record")
        );

        record.status = KaigiStatus::Ended;
        record.ended_at_ms = None;
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("an ended record without an end timestamp must fail")
                .contains("ended Kaigi record")
        );

        record.ended_at_ms = Some(9);
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("an end timestamp before creation must fail")
                .contains("must not precede creation")
        );

        record.ended_at_ms = Some(10);
        validate_kaigi_record_v1(&record)
            .expect("an ended record at its creation timestamp remains valid");
    }
    #[test]
    fn transparent_join_at_protocol_cap_rejects_without_mutating_record() {
        let (mut record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        record.participants = synthetic_multisig_account_ids(KAIGI_MAX_PARTICIPANTS_V1);
        record.participants.sort_unstable();
        let domain_id = record.id.domain_id.clone();
        let original = record.clone();
        with_seeded_kaigi_state_transaction(&domain_id, &[host, participant.clone()], |stx| {
            let error = process_join(
                stx,
                &mut record,
                KaigiAuthorization::SignedAccount(&participant),
                &participant,
                None,
                None,
                None,
                None,
            )
            .expect_err("an unbounded participant append must fail at the protocol cap");
            assert_smart_contract_error(error, "participant limit reached");
            assert_eq!(
                record, original,
                "rejected join must leave the record unchanged"
            );
        });
    }
    #[test]
    fn kaigi_record_v1_rejects_duplicate_retained_identifiers() {
        let duplicate = test_scalar(66);
        let (mut record, _, participant) = new_record(KaigiPrivacyMode::Transparent);
        record.participants = vec![participant.clone(), participant];
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("duplicate participants must fail")
                .contains("strictly sorted and unique")
        );

        let (mut record, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        record.roster_commitments = vec![
            KaigiParticipantCommitment {
                commitment: duplicate.clone(),
            },
            KaigiParticipantCommitment {
                commitment: duplicate.clone(),
            },
        ];
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("duplicate commitments must fail")
                .contains("commitments must be unique")
        );
        record.roster_commitments.clear();
        record.nullifier_log = vec![
            KaigiParticipantNullifier {
                digest: duplicate.clone(),
            },
            KaigiParticipantNullifier {
                digest: duplicate.clone(),
            },
        ];
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("duplicate nullifiers must fail")
                .contains("nullifiers must be unique")
        );
        record.nullifier_log.clear();
        record.usage_commitments = vec![duplicate.clone(), duplicate];
        record.segments_recorded = 2;
        assert!(
            validate_kaigi_record_v1(&record)
                .expect_err("duplicate usage commitments must fail")
                .contains("usage commitments must be unique")
        );
    }
    #[test]
    fn transparent_preconditions_accept_empty_payload() {
        let artifacts = PrivacyArtifacts {
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        };
        assert!(privacy::ensure_transparent_payload(&artifacts).is_ok());
    }
    #[test]
    fn transparent_preconditions_reject_privacy_artifacts() {
        let commitment = sample_commitment();
        let artifacts = PrivacyArtifacts {
            commitment: Some(&commitment),
            nullifier: None,
            roster_root: None,
            proof: None,
        };
        let err = privacy::ensure_transparent_payload(&artifacts)
            .expect_err("transparent mode should reject privacy payloads");
        match err {
            Error::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
                assert!(msg.contains("not accepted"))
            }
            other => panic!("unexpected error variant {other:?}"),
        }
    }

    #[test]
    fn zk_preconditions_require_the_governed_real_verifier() {
        let (record, host, participant) = new_record(KaigiPrivacyMode::ZkRosterV1);
        let commitment = sample_commitment();
        let nullifier = sample_nullifier(0xAB);
        with_state_transaction(|stx| {
            let root = record.roster_root();
            let context = context_from_ledger_v1(
                *stx.network_id(),
                &record.id,
                &host,
                &participant,
                1,
                KaigiAuthorizationActionV1::Join,
                &root,
            )
            .unwrap();
            let artifacts = PrivacyArtifacts {
                commitment: Some(&commitment),
                nullifier: Some(&nullifier),
                roster_root: Some(&root),
                proof: Some(&[9, 9, 9]),
            };
            assert_smart_contract_error(
                privacy::verify_authorization(stx, &artifacts, &context, None)
                    .expect_err("test builds must use the governed verifier"),
                "not configured",
            );
        });
    }
    #[test]
    fn relay_hpke_public_key_validation_enforces_v1_byte_boundaries() {
        assert!(validate_relay_hpke_public_key(&[]).is_err());
        assert!(
            validate_relay_hpke_public_key(&vec![0xA5; KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1])
                .is_ok()
        );
        assert!(
            validate_relay_hpke_public_key(&vec![
                0xA5;
                KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 + 1
            ])
            .is_err()
        );
    }
    #[test]
    fn relay_manifest_validation_enforces_rules() {
        let manifest = KaigiRelayManifest {
            hops: Vec::new(),
            expiry_ms: 1,
        };
        assert!(validate_relay_manifest(&manifest).is_err());
        let (hop_a, _) = gen_account_in("nexus");
        let (hop_b, _) = gen_account_in("nexus");
        let (hop_c, _) = gen_account_in("nexus");
        let valid = KaigiRelayManifest {
            hops: vec![
                KaigiRelayHop {
                    relay_id: hop_a.clone(),
                    hpke_public_key: vec![1, 2, 3],
                    weight: 1,
                },
                KaigiRelayHop {
                    relay_id: hop_b.clone(),
                    hpke_public_key: vec![4, 5, 6],
                    weight: 1,
                },
                KaigiRelayHop {
                    relay_id: hop_c.clone(),
                    hpke_public_key: vec![7, 8, 9],
                    weight: 1,
                },
            ],
            expiry_ms: 42,
        };
        assert!(validate_relay_manifest(&valid).is_ok());
        let mut invalid = valid.clone();
        invalid.hops[1].hpke_public_key.clear();
        assert!(validate_relay_manifest(&invalid).is_err());
        let mut oversized_key = valid.clone();
        oversized_key.hops[1].hpke_public_key =
            vec![0xA5; KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 + 1];
        assert!(validate_relay_manifest(&oversized_key).is_err());
        let mut zero_weight = valid.clone();
        zero_weight.hops[0].weight = 0;
        assert!(validate_relay_manifest(&zero_weight).is_err());
        let mut duplicate = valid.clone();
        duplicate.hops[2].relay_id = hop_a;
        assert!(validate_relay_manifest(&duplicate).is_err());
        let mut too_many = valid;
        while too_many.hops.len() <= KAIGI_RELAY_MANIFEST_MAX_HOPS_V1 {
            too_many.hops.push(too_many.hops[0].clone());
        }
        let error = validate_relay_manifest(&too_many)
            .expect_err("a nine-hop first-release relay route must be rejected");
        assert_smart_contract_error(error, "must not include more than 8 hops");
    }
    #[test]
    fn relay_manifest_rejects_two_ids_from_one_active_rekey_lineage() {
        let (domain, retired_relay, _) = sample_ids();
        let (active_relay, _) = gen_account_in("nexus");
        let (third_relay, _) = gen_account_in("nexus");
        let manifest = KaigiRelayManifest {
            hops: vec![
                KaigiRelayHop {
                    relay_id: retired_relay.clone(),
                    hpke_public_key: vec![1],
                    weight: 1,
                },
                KaigiRelayHop {
                    relay_id: active_relay.clone(),
                    hpke_public_key: vec![2],
                    weight: 1,
                },
                KaigiRelayHop {
                    relay_id: third_relay.clone(),
                    hpke_public_key: vec![3],
                    weight: 1,
                },
            ],
            expiry_ms: 1,
        };
        with_seeded_kaigi_state_transaction(&domain, &[active_relay.clone(), third_relay], |stx| {
            seed_active_account_id_rekey_lineage(
                stx,
                "kaigi-relay-lineage",
                &retired_relay,
                &active_relay,
            );
            let error = ensure_manifest_relays_registered(stx, &manifest)
                .expect_err("one relay lineage must not fill two route hops");
            assert_smart_contract_error(error, "same active account-id rekey lineage");
        });
    }
    #[test]
    fn persisted_account_id_rekey_history_survives_alias_reassignment() {
        use iroha_data_model::account::rekey::{AccountAlias, AccountRekeyRecord};
        use iroha_model_base::topology::DataSpaceId;
        let (domain, retired, _) = sample_ids();
        let (active, _) = gen_account_in("nexus");
        let (new_alias_owner, _) = gen_account_in("nexus");
        with_seeded_kaigi_state_transaction(
            &domain,
            &[active.clone(), new_alias_owner.clone()],
            |stx| {
                let alias = AccountAlias::domainless(
                    "persisted-kaigi-lineage"
                        .parse()
                        .expect("lineage alias label"),
                    DataSpaceId::UNIVERSAL,
                );
                let history = AccountRekeyRecord::new(alias.clone(), retired.clone())
                    .repoint_for_account_id_rekey(active.clone())
                    .expect("canonical account-id rekey")
                    .reassign_alias_to_account(new_alias_owner.clone())
                    .expect("later independent alias reassignment");
                stx.world.replace_account_rekey_record(history);
                stx.world
                    .insert_account_alias_binding(alias.clone(), new_alias_owner.clone());

                assert!(
                    accounts_share_active_lineage(stx, &retired, &active)
                        .expect("persisted canonical lineage"),
                    "later alias reassignment must not erase the canonical rekey edge"
                );
                assert!(
                    !accounts_share_active_lineage(stx, &retired, &new_alias_owner)
                        .expect("independent alias owner"),
                    "alias reassignment must never grant Kaigi lineage authority"
                );
                assert_eq!(
                    resolve_active_kaigi_account(stx, &retired)
                        .expect("resolve persisted successor"),
                    Some(active.clone())
                );
                let call = KaigiId::new(
                    domain.clone(),
                    Name::from_str("persisted-host").expect("call name"),
                );
                let record = KaigiRecord::from_new(
                    &NewKaigi::with_defaults(call.clone(), retired.clone()),
                    0,
                );
                store_record(
                    stx,
                    &domain,
                    kaigi_metadata_key(&call.call_name).expect("metadata key"),
                    &record,
                )
                .expect("seed predecessor-hosted call");
                let error = ensure_kaigi_account_can_unregister(stx, &active)
                    .expect_err("the successor must remain protected after alias reassignment");
                assert_invariant_error(error, "referenced by active Kaigi");
                let error = Unregister::account(new_alias_owner.clone())
                    .execute(&ALICE_ID, stx)
                    .expect_err("alias-owner teardown must preserve the canonical rekey edge");
                assert_invariant_error(error, "history is required by native Kaigi state");
                assert!(stx.world.account(&new_alias_owner).is_ok());
                assert_eq!(
                    stx.world.account_aliases.get(&alias),
                    Some(&new_alias_owner)
                );
                assert!(stx.world.account_rekey_records.get(&alias).is_some());
            },
        );
    }
    #[test]
    fn account_dependency_guard_and_rekey_graph_ignore_unrelated_oversized_history() {
        use iroha_data_model::account::rekey::{
            AccountAlias, AccountRekeyRecord, AccountRekeyTransitionProvenance,
        };
        use iroha_model_base::topology::DataSpaceId;
        let (domain, predecessor, _) = sample_ids();
        let (terminal, _) = gen_account_in("nexus");
        let (unrelated_predecessor, _) = gen_account_in("nexus");
        let (unrelated_terminal, _) = gen_account_in("nexus");
        with_seeded_kaigi_state_transaction(
            &domain,
            &[terminal.clone(), unrelated_terminal.clone()],
            |stx| {
                let alias = AccountAlias::domainless(
                    "targeted-kaigi-lineage".parse().expect("alias label"),
                    DataSpaceId::UNIVERSAL,
                );
                stx.world.replace_account_rekey_record(
                    AccountRekeyRecord::new(alias, predecessor.clone())
                        .repoint_for_account_id_rekey(terminal.clone())
                        .expect("target rekey history"),
                );
                let unrelated_alias = AccountAlias::domainless(
                    "oversized-unrelated-kaigi-lineage"
                        .parse()
                        .expect("alias label"),
                    DataSpaceId::UNIVERSAL,
                );
                let mut oversized =
                    AccountRekeyRecord::new(unrelated_alias, unrelated_terminal.clone());
                oversized.previous_account_ids = vec![
                    unrelated_predecessor.clone();
                    crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT
                ];
                oversized.transition_provenance = vec![
                    AccountRekeyTransitionProvenance::AccountIdRekey;
                    crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT
                ];
                stx.world.replace_account_rekey_record(oversized);

                assert_eq!(
                    resolve_active_kaigi_account(stx, &predecessor)
                        .expect("unrelated history must not affect targeted resolution"),
                    Some(terminal.clone())
                );
                ensure_kaigi_account_can_unregister(stx, &terminal)
                    .expect("unrelated oversized history must not affect the dependency guard");
                let error = resolve_active_kaigi_account(stx, &unrelated_predecessor)
                    .expect_err("the oversized requested lineage must hit the work bound");
                assert_invariant_error(error, "occurrence work limit");
            },
        );
    }
    #[test]
    fn rekey_record_removal_batches_maximum_lineage_component() {
        use iroha_data_model::account::rekey::AccountAlias;
        use iroha_model_base::topology::DataSpaceId;

        let (domain, _, _) = sample_ids();
        let accounts = synthetic_multisig_account_ids(crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT);
        let alias = AccountAlias::domainless(
            "maximum-batched-kaigi-lineage"
                .parse()
                .expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let record = account_id_rekey_chain_record(alias.clone(), &accounts);
        with_seeded_kaigi_state_transaction(&domain, &[], |stx| {
            stx.world.replace_account_rekey_record(record.clone());

            ensure_kaigi_account_rekey_records_can_be_removed(
                stx,
                &BTreeSet::from([alias.clone()]),
                "testing maximum batched lineage cleanup",
            )
            .expect("one maximum-size lineage component must be inspected once");
        });
    }
    #[test]
    fn rekey_record_removal_bounds_selected_history_before_endpoint_collection() {
        use iroha_data_model::account::rekey::AccountAlias;
        use iroha_model_base::topology::DataSpaceId;

        let (domain, _, _) = sample_ids();
        let occurrences_per_alias = crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT / 2 + 1;
        let first_accounts = synthetic_multisig_account_ids(occurrences_per_alias);
        let second_accounts = synthetic_multisig_account_ids(occurrences_per_alias);
        let first_alias = AccountAlias::domainless(
            "bounded-kaigi-cleanup-a".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let second_alias = AccountAlias::domainless(
            "bounded-kaigi-cleanup-b".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let first_record = account_id_rekey_chain_record(first_alias.clone(), &first_accounts);
        let second_record = account_id_rekey_chain_record(second_alias.clone(), &second_accounts);
        with_seeded_kaigi_state_transaction(&domain, &[], |stx| {
            stx.world.replace_account_rekey_record(first_record.clone());
            stx.world
                .replace_account_rekey_record(second_record.clone());

            let error = ensure_kaigi_account_rekey_records_can_be_removed(
                stx,
                &BTreeSet::from([first_alias.clone(), second_alias.clone()]),
                "testing aggregate cleanup bounds",
            )
            .expect_err("selected history must be bounded before endpoint cloning");
            assert_invariant_error(error, "selected account-id rekey history exceeds");
        });
    }
    #[test]
    fn persisted_rekey_graph_accepts_small_disconnected_seed_components() {
        use iroha_data_model::account::rekey::AccountAlias;
        use iroha_model_base::topology::DataSpaceId;

        let (domain, _, _) = sample_ids();
        let first_accounts = synthetic_multisig_account_ids(3);
        let second_accounts = synthetic_multisig_account_ids(3);
        let first_alias = AccountAlias::domainless(
            "small-disconnected-kaigi-a".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let second_alias = AccountAlias::domainless(
            "small-disconnected-kaigi-b".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let first_record = account_id_rekey_chain_record(first_alias, &first_accounts);
        let second_record = account_id_rekey_chain_record(second_alias, &second_accounts);
        with_seeded_kaigi_state_transaction(&domain, &[], |stx| {
            stx.world.replace_account_rekey_record(first_record.clone());
            stx.world
                .replace_account_rekey_record(second_record.clone());

            let graph = persisted_kaigi_rekey_graph(
                &stx.world,
                [first_accounts[0].clone(), second_accounts[0].clone()],
            )
            .expect("small disconnected components fit the aggregate work budget");
            assert_eq!(graph.forward.len(), 4);
        });
    }
    #[test]
    fn persisted_rekey_graph_bounds_aggregate_disconnected_component_work() {
        use iroha_data_model::account::rekey::AccountAlias;
        use iroha_model_base::topology::DataSpaceId;

        let (domain, _, _) = sample_ids();
        let occurrences_per_component = crate::sns::ACCOUNT_REKEY_LINEAGE_WORK_LIMIT / 2 + 1;
        let first_accounts = synthetic_multisig_account_ids(occurrences_per_component);
        let second_accounts = synthetic_multisig_account_ids(occurrences_per_component);
        let first_alias = AccountAlias::domainless(
            "aggregate-bounded-kaigi-a".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let second_alias = AccountAlias::domainless(
            "aggregate-bounded-kaigi-b".parse().expect("alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let first_record = account_id_rekey_chain_record(first_alias, &first_accounts);
        let second_record = account_id_rekey_chain_record(second_alias, &second_accounts);
        with_seeded_kaigi_state_transaction(&domain, &[], |stx| {
            stx.world.replace_account_rekey_record(first_record.clone());
            stx.world
                .replace_account_rekey_record(second_record.clone());

            persisted_kaigi_rekey_graph(&stx.world, [first_accounts[0].clone()])
                .expect("the first component fits the per-request work budget");
            persisted_kaigi_rekey_graph(&stx.world, [second_accounts[0].clone()])
                .expect("the second component fits the per-request work budget");
            let error = match persisted_kaigi_rekey_graph(
                &stx.world,
                [first_accounts[0].clone(), second_accounts[0].clone()],
            ) {
                Ok(_) => panic!("aggregate disconnected work must share one request budget"),
                Err(error) => error,
            };
            assert_invariant_error(error, "occurrence work limit");
        });
    }
    #[test]
    fn duplicate_rekey_edges_remain_supported_until_the_last_alias_is_removed() {
        use iroha_data_model::account::rekey::{AccountAlias, AccountRekeyRecord};
        use iroha_model_base::topology::DataSpaceId;
        let (domain, predecessor, _) = sample_ids();
        let (terminal, _) = gen_account_in("nexus");
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&terminal), |stx| {
            let first_alias = AccountAlias::domainless(
                "duplicate-edge-a".parse().expect("alias label"),
                DataSpaceId::UNIVERSAL,
            );
            let second_alias = AccountAlias::domainless(
                "duplicate-edge-b".parse().expect("alias label"),
                DataSpaceId::UNIVERSAL,
            );
            for alias in [&first_alias, &second_alias] {
                stx.world.replace_account_rekey_record(
                    AccountRekeyRecord::new(alias.clone(), predecessor.clone())
                        .repoint_for_account_id_rekey(terminal.clone())
                        .expect("duplicate canonical edge"),
                );
            }
            assert_eq!(
                stx.world.account_rekey_records_by_account.get(&predecessor),
                Some(&BTreeSet::from([first_alias.clone(), second_alias.clone()]))
            );
            assert_eq!(
                resolve_active_kaigi_account(stx, &predecessor).expect("duplicate edge support"),
                Some(terminal.clone())
            );

            stx.world.remove_account_rekey_record(&first_alias);
            assert_eq!(
                stx.world.account_rekey_records_by_account.get(&predecessor),
                Some(&BTreeSet::from([second_alias.clone()]))
            );
            assert_eq!(
                resolve_active_kaigi_account(stx, &predecessor)
                    .expect("remaining duplicate edge support"),
                Some(terminal.clone())
            );

            stx.world.remove_account_rekey_record(&second_alias);
            assert!(
                stx.world
                    .account_rekey_records_by_account
                    .get(&predecessor)
                    .is_none()
            );
            assert_eq!(
                resolve_active_kaigi_account(stx, &predecessor).expect("removed edge resolution"),
                None
            );
        });
    }
    #[test]
    fn persisted_rekey_history_rejects_a_registered_predecessor() {
        use iroha_data_model::account::rekey::{AccountAlias, AccountRekeyRecord};
        use iroha_model_base::topology::DataSpaceId;
        let (domain, predecessor, _) = sample_ids();
        let (terminal, _) = gen_account_in("nexus");
        with_seeded_kaigi_state_transaction(
            &domain,
            &[predecessor.clone(), terminal.clone()],
            |stx| {
                let alias = AccountAlias::domainless(
                    "resurrected-kaigi-predecessor"
                        .parse()
                        .expect("lineage alias label"),
                    DataSpaceId::UNIVERSAL,
                );
                let history = AccountRekeyRecord::new(alias.clone(), predecessor.clone())
                    .repoint_for_account_id_rekey(terminal.clone())
                    .expect("canonical account-id rekey");
                stx.world.replace_account_rekey_record(history);

                let error = resolve_active_kaigi_account(stx, &predecessor)
                    .expect_err("a registered predecessor must not regain Kaigi authority");
                assert_invariant_error(error, "one registered terminal successor");
                let error = accounts_share_active_lineage(stx, &predecessor, &predecessor)
                    .expect_err("same-ID comparison must not bypass lineage validation");
                assert_invariant_error(error, "one registered terminal successor");
                let call = KaigiId::new(
                    domain.clone(),
                    Name::from_str("resurrected-host-create").expect("call name"),
                );
                let error = CreateKaigi {
                    call: NewKaigi::with_defaults(call.clone(), predecessor.clone()),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&predecessor, stx)
                .expect_err("a resurrected predecessor must not create stuck Kaigi state");
                assert_invariant_error(error, "one registered terminal successor");
                let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
                assert!(
                    stx.world
                        .domain(&domain)
                        .expect("domain")
                        .metadata()
                        .get(&key)
                        .is_none()
                );
            },
        );
    }
    #[test]
    fn account_registration_rejects_a_retired_rekey_predecessor() {
        use iroha_data_model::account::rekey::{AccountAlias, AccountRekeyRecord};
        use iroha_model_base::topology::DataSpaceId;
        let (domain, predecessor, _) = sample_ids();
        let (terminal, _) = gen_account_in("nexus");
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&terminal), |stx| {
            let alias = AccountAlias::domainless(
                "retired-registration".parse().expect("lineage alias label"),
                DataSpaceId::UNIVERSAL,
            );
            let history = AccountRekeyRecord::new(alias.clone(), predecessor.clone())
                .repoint_for_account_id_rekey(terminal.clone())
                .expect("canonical account-id rekey");
            stx.world.replace_account_rekey_record(history);

            let error = Register::account(Account::new(predecessor.clone()))
                .execute(&ALICE_ID, stx)
                .expect_err("canonical rekey predecessors must remain retired");
            assert_invariant_error(error, "retired canonical account-id rekey predecessor");
            assert!(matches!(
                stx.world.account(&predecessor),
                Err(FindError::Account(account)) if account == predecessor
            ));
        });
    }
    #[test]
    fn persisted_rekey_history_rejects_a_mismatched_storage_alias() {
        use iroha_data_model::account::rekey::{AccountAlias, AccountRekeyRecord};
        use iroha_model_base::topology::DataSpaceId;
        let (domain, predecessor, _) = sample_ids();
        let (terminal, _) = gen_account_in("nexus");
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&terminal), |stx| {
            let stored_alias = AccountAlias::domainless(
                "stored-kaigi-lineage".parse().expect("stored alias label"),
                DataSpaceId::UNIVERSAL,
            );
            let embedded_alias = AccountAlias::domainless(
                "embedded-kaigi-lineage"
                    .parse()
                    .expect("embedded alias label"),
                DataSpaceId::UNIVERSAL,
            );
            let history = AccountRekeyRecord::new(embedded_alias, predecessor.clone())
                .repoint_for_account_id_rekey(terminal.clone())
                .expect("canonical account-id rekey");
            stx.world
                .account_rekey_records
                .insert(stored_alias.clone(), history);
            for account_id in [&predecessor, &terminal] {
                stx.world
                    .account_rekey_records_by_account
                    .insert(account_id.clone(), BTreeSet::from([stored_alias.clone()]));
            }

            let error = resolve_active_kaigi_account(stx, &predecessor)
                .expect_err("the persisted alias key must authenticate its payload");
            assert_invariant_error(error, "key does not match its embedded alias");
        });
    }
    pub(super) fn sample_ids() -> (DomainId, AccountId, AccountId) {
        let domain = DomainId::try_new("nexus", "universal").expect("domain id");
        let (host, _) = gen_account_in("nexus");
        let (participant, _) = gen_account_in("nexus");
        (domain, host, participant)
    }
    fn synthetic_multisig_account_ids(count: usize) -> Vec<AccountId> {
        use iroha_data_model::account::{MultisigMember, MultisigPolicy};

        let (base, _) = gen_account_in("nexus");
        let public_key = base
            .try_signatory()
            .expect("sample account has one signatory")
            .clone();
        (1..=count)
            .map(|weight| {
                let weight = u16::try_from(weight).expect("synthetic account weight fits u16");
                let member = MultisigMember::new(public_key.clone(), weight)
                    .expect("non-zero synthetic member weight");
                let policy = MultisigPolicy::new(1, vec![member])
                    .expect("single-member synthetic multisig policy");
                AccountId::new_multisig(policy)
            })
            .collect()
    }
    fn account_id_rekey_chain_record(
        alias: AccountAlias,
        accounts: &[AccountId],
    ) -> iroha_data_model::account::rekey::AccountRekeyRecord {
        use iroha_data_model::account::rekey::AccountRekeyRecord;

        assert!(accounts.len() >= 2, "a rekey chain needs at least one edge");
        let mut record = AccountRekeyRecord::new(alias, accounts[0].clone());
        record.previous_account_ids = accounts[..accounts.len() - 1].to_vec();
        record.transition_provenance = vec![
            AccountRekeyTransitionProvenance::AccountIdRekey;
            record.previous_account_ids.len()
        ];
        record.active_account_id = accounts.last().expect("non-empty account chain").clone();
        record
    }
    pub(super) fn new_record(mode: KaigiPrivacyMode) -> (KaigiRecord, AccountId, AccountId) {
        let (domain, host, participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("daily").unwrap());
        let mut template = NewKaigi::with_defaults(call, host.clone());
        template.privacy_mode = mode;
        let mut record = KaigiRecord::from_new(&template, 1);
        if mode == KaigiPrivacyMode::ZkRosterV1 {
            record.host_commitment = Some(KaigiParticipantCommitment {
                commitment: test_scalar(10_000),
            });
            record.push_nullifier(sample_nullifier(0));
        }
        (record, host, participant)
    }
    fn test_scalar(value: u64) -> KaigiAuthorizationScalarV1 {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        KaigiAuthorizationScalarV1::from_le_bytes(bytes).unwrap()
    }
    fn install_private_create(
        stx: &mut StateTransaction<'_, '_>,
        template: NewKaigi,
    ) -> AuthorizationFixtureV1 {
        let record = KaigiRecord::from_new(&template, 0);
        let artifacts = authorization_fixture_v1(
            stx,
            &record,
            &record.host,
            0,
            KaigiAuthorizationActionV1::HostCreate,
            77,
        );
        CreateKaigi {
            call: template,
            commitment: Some(artifacts.commitment),
            nullifier: Some(artifacts.nullifier),
            roster_root: Some(artifacts.root),
            proof: Some(artifacts.proof.clone()),
        }
        .execute(&record.host, stx)
        .expect("real private create");
        artifacts
    }
    pub(super) fn sample_commitment() -> KaigiParticipantCommitment {
        KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x11; 32]).unwrap(),
        }
    }
    pub(super) fn sample_nullifier(tag: u8) -> KaigiParticipantNullifier {
        KaigiParticipantNullifier {
            digest: test_scalar(u64::from(tag)),
        }
    }
    pub(super) fn with_state_transaction<F>(f: F)
    where
        F: FnMut(&mut StateTransaction<'_, '_>),
    {
        with_state_transaction_at(0, f);
    }
    fn with_state_transaction_at<F>(creation_time_ms: u64, mut f: F)
    where
        F: FnMut(&mut StateTransaction<'_, '_>),
    {
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(World::default(), kura, query);
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero height"),
            None,
            None,
            creation_time_ms,
            0,
        );
        let mut block = state.block(header);
        {
            let mut stx = block.transaction();
            f(&mut stx);
        }
    }
    fn with_seeded_kaigi_state_transaction<F>(domain: &DomainId, accounts: &[AccountId], mut f: F)
    where
        F: FnMut(&mut StateTransaction<'_, '_>),
    {
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let seeded_domain = Domain::new(domain.clone()).build(&ALICE_ID);
        let seeded_accounts = accounts
            .iter()
            .cloned()
            .map(|account| Account::new(account).build(&ALICE_ID));
        let state = State::new(
            World::with(
                [seeded_domain],
                seeded_accounts,
                std::iter::empty::<AssetDefinition>(),
            ),
            kura,
            query,
        );
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        {
            let mut stx = block.transaction();
            f(&mut stx);
        }
    }
    fn seed_active_account_id_rekey_lineage(
        stx: &mut StateTransaction<'_, '_>,
        label: &str,
        retired: &AccountId,
        active: &AccountId,
    ) {
        use iroha_data_model::{
            account::{
                AccountAddress,
                rekey::{AccountAlias, AccountRekeyRecord},
            },
            sns::{NameControllerV1, NameRecordV1},
        };
        use iroha_model_base::topology::DataSpaceId;
        let alias = AccountAlias::domainless(
            label.parse().expect("lineage alias label"),
            DataSpaceId::UNIVERSAL,
        );
        let selector =
            crate::sns::selector_for_account_alias(&alias, stx.world.dataspace_catalog())
                .expect("lineage alias selector");
        let address = AccountAddress::from_account_id(active).expect("active account address");
        let lease = NameRecordV1::new(
            selector.clone(),
            active.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        stx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&lease),
        );
        stx.world.replace_account_rekey_record(
            AccountRekeyRecord::new(alias.clone(), retired.clone())
                .repoint_for_account_id_rekey(active.clone())
                .expect("canonical account-id rekey fixture"),
        );
        stx.world
            .insert_account_alias_binding(alias, active.clone());
    }
    #[test]
    fn transparent_join_and_leave_updates_participants_only() {
        let (mut record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        let domain_id = record.id.domain_id.clone();
        with_seeded_kaigi_state_transaction(
            &domain_id,
            &[host.clone(), participant.clone()],
            |stx| {
                let grant = process_join(
                    stx,
                    &mut record,
                    KaigiAuthorization::SignedAccount(&participant),
                    &participant,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("transparent join");
                assert_eq!(grant, AccessGrant::Default);
                assert!(record.has_participant(&participant));
                assert!(record.roster_commitments.is_empty());
                let leave_grant = process_leave(
                    stx,
                    &mut record,
                    &participant,
                    &participant,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("transparent leave");
                assert_eq!(leave_grant, AccessGrant::Default);
                assert!(!record.has_participant(&participant));
                let _ = process_join(
                    stx,
                    &mut record,
                    KaigiAuthorization::SignedAccount(&host),
                    &participant,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("host can re-invite");
            },
        );
    }
    #[test]
    fn account_dependency_index_tracks_call_lifecycle_and_filters_relay_home_checks() {
        let (record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = call.domain_id.clone();
        let dependency = (
            KAIGI_DEPENDENCY_ACTIVE_CALL,
            domain.clone(),
            kaigi_metadata_key(&call.call_name).expect("call metadata key"),
        );
        with_seeded_kaigi_state_transaction(&domain, &[host.clone(), participant.clone()], |stx| {
            create_call(stx, &record, &host);
            assert!(
                stx.world
                    .kaigi_account_dependencies
                    .get(&host)
                    .is_some_and(|dependencies| dependencies.contains(&dependency))
            );
            ensure_kaigi_relay_home_change_allowed(stx, &host, &domain, None)
                .expect("an active-call host reference is not retained relay state");
            assert_invariant_error(
                ensure_kaigi_account_can_unregister(stx, &host)
                    .expect_err("an active-call host must remain registered"),
                "referenced by active Kaigi",
            );

            JoinKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("join participant");
            assert!(
                stx.world
                    .kaigi_account_dependencies
                    .get(&participant)
                    .is_some_and(|dependencies| dependencies.contains(&dependency))
            );

            LeaveKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("leave participant");
            assert!(
                stx.world
                    .kaigi_account_dependencies
                    .get(&participant)
                    .is_none()
            );
            ensure_kaigi_account_can_unregister(stx, &participant)
                .expect("a departed participant has no retained Kaigi dependency");

            EndKaigi {
                call_id: call.clone(),
                ended_at_ms: Some(0),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("end Kaigi");
            assert!(stx.world.kaigi_account_dependencies.get(&host).is_none());
            ensure_kaigi_account_can_unregister(stx, &host)
                .expect("an ended Kaigi has no retained account dependency");
        });
    }
    #[test]
    fn account_dependency_index_rolls_back_with_transaction_metadata() {
        let (record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = call.domain_id.clone();
        let dependency = (
            KAIGI_DEPENDENCY_ACTIVE_CALL,
            domain.clone(),
            kaigi_metadata_key(&call.call_name).expect("call metadata key"),
        );
        let state = State::new(
            World::with(
                [Domain::new(domain.clone()).build(&ALICE_ID)],
                [host.clone(), participant.clone()]
                    .map(|account| Account::new(account).build(&ALICE_ID)),
                std::iter::empty::<AssetDefinition>(),
            ),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero height"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        {
            let mut transaction = block.transaction();
            create_call(&mut transaction, &record, &host);
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            JoinKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, &mut transaction)
            .expect("join participant in discarded transaction");
            assert!(
                transaction
                    .world
                    .kaigi_account_dependencies
                    .get(&participant)
                    .is_some_and(|dependencies| dependencies.contains(&dependency))
            );
        }
        assert!(
            block
                .world
                .kaigi_account_dependencies
                .get(&participant)
                .is_none()
        );
        let stored: KaigiRecord = block
            .world
            .domain(&domain)
            .expect("Kaigi domain")
            .metadata()
            .get(&dependency.2)
            .expect("Kaigi metadata")
            .clone()
            .try_into_any_norito()
            .expect("decode Kaigi metadata");
        assert!(stored.participants.is_empty());
        assert!(
            block
                .world
                .kaigi_account_dependencies
                .get(&host)
                .is_some_and(|dependencies| dependencies.contains(&dependency))
        );
    }
    #[test]
    fn record_storage_preserves_final_scalar_bytes_without_hint_slots() {
        let (record, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        let json = norito::json::to_json(&record).unwrap();
        assert!(!json.contains("alias_tag"));
        assert!(!json.contains("issued_at_ms"));
        let restored: KaigiRecord = norito::json::from_str(&json).unwrap();
        assert_eq!(restored, record);
    }
    #[test]
    fn retained_call_decode_rejects_retired_hint_fields_instead_of_scrubbing() {
        let (record, _, _) = new_record(KaigiPrivacyMode::ZkRosterV1);
        let key = metadata_key(&record.id).unwrap();
        for (field, hint) in [
            ("host_commitment", "alias_tag"),
            ("nullifier_log", "issued_at_ms"),
        ] {
            let mut json = norito::json::to_value(&record).unwrap();
            let artifact = json.as_object_mut().unwrap().get_mut(field).unwrap();
            let object = if field == "nullifier_log" {
                artifact.as_array_mut().unwrap()[0].as_object_mut().unwrap()
            } else {
                artifact.as_object_mut().unwrap()
            };
            object.insert(hint.into(), norito::json::Value::Null);
            let value = Json::try_new(json).unwrap();
            assert!(decode_stored_kaigi_record(&record.id.domain_id, &key, &value).is_err());
        }
    }

    #[test]
    fn private_join_leave_and_rejoin_consume_exact_sequences_with_real_proofs() {
        let (mut record, host, participant) = new_record(KaigiPrivacyMode::ZkRosterV1);
        let domain = record.id.domain_id.clone();
        with_seeded_kaigi_state_transaction(&domain, &[host, participant.clone()], |stx| {
            let joined = authorization_fixture_v1(
                stx,
                &record,
                &participant,
                1,
                KaigiAuthorizationActionV1::Join,
                17,
            );
            let grant = process_join(
                stx,
                &mut record,
                KaigiAuthorization::SignedAccount(&participant),
                &participant,
                Some(joined.commitment),
                Some(joined.nullifier),
                Some(joined.root),
                Some(&joined.proof),
            )
            .unwrap();
            assert_eq!(grant, AccessGrant::PrivacyAuthorized);
            assert!(record.participants.is_empty());
            assert_eq!(record.roster_commitments, vec![joined.commitment]);
            assert!(record.has_nullifier(&joined.nullifier));
            let before_duplicate = record.clone();
            assert!(
                process_join(
                    stx,
                    &mut record,
                    KaigiAuthorization::SignedAccount(&participant),
                    &participant,
                    Some(joined.commitment),
                    Some(joined.nullifier),
                    Some(joined.root),
                    Some(&joined.proof)
                )
                .is_err()
            );
            assert_eq!(record, before_duplicate);
            let left = authorization_fixture_v1(
                stx,
                &record,
                &participant,
                1,
                KaigiAuthorizationActionV1::Leave,
                17,
            );
            assert_eq!(joined.commitment, left.commitment);
            assert_ne!(joined.nullifier, left.nullifier);
            assert_eq!(
                process_leave(
                    stx,
                    &mut record,
                    &participant,
                    &participant,
                    Some(left.commitment),
                    Some(left.nullifier),
                    Some(left.root),
                    Some(&left.proof)
                )
                .unwrap(),
                AccessGrant::PrivacyAuthorized
            );
            assert!(record.roster_commitments.is_empty());
            assert_eq!(
                record
                    .private_participation
                    .prepare_join(&participant)
                    .unwrap(),
                2
            );
            assert!(record.has_nullifier(&left.nullifier));
            let rejoined = authorization_fixture_v1(
                stx,
                &record,
                &participant,
                2,
                KaigiAuthorizationActionV1::Join,
                19,
            );
            assert_ne!(rejoined.commitment, joined.commitment);
            process_join(
                stx,
                &mut record,
                KaigiAuthorization::SignedAccount(&participant),
                &participant,
                Some(rejoined.commitment),
                Some(rejoined.nullifier),
                Some(rejoined.root),
                Some(&rejoined.proof),
            )
            .unwrap();
            let before_replay = record.clone();
            assert!(
                process_leave(
                    stx,
                    &mut record,
                    &participant,
                    &participant,
                    Some(left.commitment),
                    Some(left.nullifier),
                    Some(left.root),
                    Some(&left.proof)
                )
                .is_err()
            );
            assert_eq!(record, before_replay);
        });
    }

    #[test]
    fn private_join_reserves_the_configured_participant_limit() {
        let (mut record, host, participant) = new_record(KaigiPrivacyMode::ZkRosterV1);
        let (other, _) = gen_account_in("nexus");
        let domain = record.id.domain_id.clone();
        record.max_participants = Some(1);
        with_seeded_kaigi_state_transaction(
            &domain,
            &[host, participant.clone(), other.clone()],
            |stx| {
                let joined = authorization_fixture_v1(
                    stx,
                    &record,
                    &participant,
                    1,
                    KaigiAuthorizationActionV1::Join,
                    17,
                );
                process_join(
                    stx,
                    &mut record,
                    KaigiAuthorization::SignedAccount(&participant),
                    &participant,
                    Some(joined.commitment),
                    Some(joined.nullifier),
                    Some(joined.root),
                    Some(&joined.proof),
                )
                .unwrap();
                let root = record.roster_root();
                let before = record.clone();
                let error = process_join(
                    stx,
                    &mut record,
                    KaigiAuthorization::SignedAccount(&other),
                    &other,
                    Some(sample_commitment()),
                    Some(sample_nullifier(0xDD)),
                    Some(root),
                    Some(&[2]),
                )
                .unwrap_err();
                assert_smart_contract_error(error, "participant limit reached");
                assert_eq!(record, before);
            },
        );
    }
    #[test]
    fn create_kaigi_emits_roster_summary_and_manifest() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("relayed").unwrap());
        let manifest = sample_manifest();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host account");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
            template.relay_manifest = Some(manifest.clone());
            install_private_create(stx, template);
            let events = stx.world.take_external_events();
            let summary = extract_roster_summary(&events).expect("roster summary event");
            assert_eq!(summary.call, call);
            assert_eq!(summary.privacy_mode, KaigiPrivacyMode::ZkRosterV1);
            assert_eq!(summary.participant_count, 0);
            assert_eq!(summary.commitment_count, 0);
            assert_eq!(summary.nullifier_count, 1);
            let relay = extract_manifest_summary(&events).expect("relay manifest summary");
            assert_eq!(relay.call, call);
            assert_eq!(relay.hop_count, 3);
            assert_eq!(relay.expiry_ms, 42);
        });
    }
    #[test]
    fn create_kaigi_requires_registered_relays() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("registered-relays").expect("call name"),
        );
        let manifest = sample_manifest();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host account");
            for hop in &manifest.hops {
                Register::account(Account::new(hop.relay_id.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register relay account");
                add_relay_to_allowlist(stx, &domain, &hop.relay_id);
            }
            stx.world.take_external_events();

            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            let error = CreateKaigi {
                call: template.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("create must reject an unregistered manifest relay");
            assert_smart_contract_error(error, "not registered");
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());

            for hop in &manifest.hops {
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: hop.relay_id.clone(),
                        hpke_public_key: hop.hpke_public_key.clone(),
                        bandwidth_class: 1,
                    },
                }
                .execute(&hop.relay_id, stx)
                .expect("register relay descriptor");
            }
            stx.world.take_external_events();
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create succeeds after every relay is registered");
        });
    }
    #[test]
    fn create_kaigi_rejects_zero_participant_limit_without_mutation() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("zero-participant-limit").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.max_participants = Some(0);
            let error = CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("zero max_participants must reject");
            assert_smart_contract_error(error, "greater than zero");
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn create_kaigi_rejects_participant_limit_above_v1_cap_without_mutation() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("over-cap-participant-limit").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.max_participants = Some(
                u32::try_from(KAIGI_MAX_PARTICIPANTS_V1 + 1)
                    .expect("participant limit plus one fits u32"),
            );
            let error = CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("max_participants above the V1 cap must reject");
            assert_smart_contract_error(error, "must not exceed 4096");
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn record_store_and_dependency_rebuild_reject_invalid_v1_shape_atomically() {
        let (mut record, host, _) = new_record(KaigiPrivacyMode::Transparent);
        let domain = record.id.domain_id.clone();
        let key = kaigi_metadata_key(&record.id.call_name).expect("metadata key");
        record.max_participants = Some(
            u32::try_from(KAIGI_MAX_PARTICIPANTS_V1 + 1)
                .expect("participant limit plus one fits u32"),
        );
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let error = store_record(stx, &domain, key.clone(), &record)
                .expect_err("native store must reject an invalid record shape");
            assert_smart_contract_error(error, "must not exceed 4096");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_none(),
                "rejected store must not mutate metadata"
            );

            record.max_participants = None;
            record.status = KaigiStatus::Ended;
            record.ended_at_ms = None;
            stx.world
                .domain_mut(&domain)
                .expect("domain")
                .metadata_mut()
                .insert(
                    key.clone(),
                    Json::try_new(record.clone()).expect("serialize legacy invalid record"),
                );
            let error = collect_kaigi_account_dependencies_at(&stx.world, None)
                .expect_err("snapshot rebuild must reject an invalid retained lifecycle");
            assert_invariant_error(error, "ended Kaigi record must retain an end timestamp");
            let stored: KaigiRecord = stx
                .world
                .domain(&domain)
                .expect("domain")
                .metadata()
                .get(&key)
                .expect("legacy record remains present")
                .clone()
                .try_into_any_norito()
                .expect("decode legacy record");
            assert_eq!(
                stored, record,
                "failed rebuild validation must not rewrite state"
            );
        });
    }
    #[test]
    fn create_kaigi_rejects_record_above_json_bound_without_mutation() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("oversized-record").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.description = Some("x".repeat(KAIGI_RECORD_MAX_JSON_BYTES_V1));
            let error = CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("an over-limit encoded record must reject");
            let message = error.to_string();
            assert!(
                message.contains("JSON") && message.contains("limit"),
                "unexpected error: {message}"
            );
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn create_kaigi_rejects_unregistered_host_without_mutation() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("unregistered-host").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(&domain, &[], |stx| {
            let error = CreateKaigi {
                call: NewKaigi::with_defaults(call.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("an unregistered host must not create a Kaigi record");
            assert!(
                matches!(&error, Error::Find(FindError::Account(account)) if account == &host),
                "unexpected unregistered-host rejection: {error:?}",
            );
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain")
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn create_kaigi_rejects_third_party_billing_account_without_mutation() {
        let (domain, host, billing_account) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("third-party-billing").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(
            &domain,
            &[host.clone(), billing_account.clone()],
            |stx| {
                let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
                template.billing_account = Some(billing_account.clone());
                let error = CreateKaigi {
                    call: template,
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&host, stx)
                .expect_err("an unsigned billing account must not be charged");
                assert_smart_contract_error(error, "must be the signed host");
                let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
                assert!(
                    stx.world
                        .domain(&domain)
                        .expect("domain")
                        .metadata()
                        .get(&key)
                        .is_none()
                );
                assert!(stx.world.take_external_events().is_empty());
            },
        );
    }
    #[test]
    fn create_kaigi_accepts_explicit_host_billing_account() {
        let (domain, host, _) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("host-billing").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.billing_account = Some(host.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("the signed host may explicitly bill itself");
            assert_eq!(
                load_call_record(stx, &call).billing_account,
                Some(host.clone())
            );
        });
    }
    #[test]
    fn create_and_set_kaigi_reject_expired_relay_manifests() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("manifest-expiry").expect("call name"),
        );
        let mut manifest = sample_manifest();
        manifest.expiry_ms = 42;
        with_state_transaction_at(42, |stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host account");
            register_manifest_relays(stx, &domain, &manifest);

            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            let error = CreateKaigi {
                call: template.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("create must reject a manifest expiring at the current block");
            assert_smart_contract_error(error, "expiry");
            assert!(stx.world.take_external_events().is_empty());

            template
                .relay_manifest
                .as_mut()
                .expect("manifest")
                .expiry_ms = 43;
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("future-dated manifest is admitted");
            let current = load_call_record(stx, &call);
            stx.world.take_external_events();

            let error = SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(manifest.clone()),
            }
            .execute(&host, stx)
            .expect_err("replacement must reject an expired manifest");
            assert_smart_contract_error(error, "expiry");
            assert_eq!(load_call_record(stx, &call), current);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn private_create_stores_the_real_host_commitment_and_create_nullifier() {
        let (domain, host, _) = sample_ids();
        let call = KaigiId::new(domain.clone(), "private-host".parse().unwrap());
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
            let artifacts = install_private_create(stx, template);
            let record = load_call_record(stx, &call);
            assert_eq!(record.host_commitment, Some(artifacts.commitment));
            assert!(record.has_nullifier(&artifacts.nullifier));
            assert_eq!(record.status, KaigiStatus::Active);
            assert!(record.private_participation.entries().is_empty());
        });
    }
    #[test]
    fn private_end_requires_original_host_opening_active_signature_and_unique_action() {
        let (domain, host, participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), "private-end".parse().unwrap());
        with_seeded_kaigi_state_transaction(&domain, &[host.clone(), participant.clone()], |stx| {
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
            let created = install_private_create(stx, template.clone());
            let record = load_call_record(stx, &call);
            let ended = authorization_fixture_v1(
                stx,
                &record,
                &host,
                0,
                KaigiAuthorizationActionV1::HostEnd,
                77,
            );
            assert_eq!(created.commitment, ended.commitment);
            assert_ne!(created.nullifier, ended.nullifier);
            let end = EndKaigi {
                call_id: call.clone(),
                ended_at_ms: Some(0),
                commitment: Some(ended.commitment),
                nullifier: Some(ended.nullifier),
                roster_root: Some(ended.root),
                proof: Some(ended.proof),
            };
            let mut replay_create = end.clone();
            replay_create.nullifier = Some(created.nullifier);
            assert!(replay_create.execute(&host, stx).is_err());
            assert!(end.clone().execute(&participant, stx).is_err());
            assert_eq!(load_call_record(stx, &call), record);
            end.clone().execute(&host, stx).unwrap();
            let final_record = load_call_record(stx, &call);
            assert_eq!(final_record.status, KaigiStatus::Ended);
            assert_eq!(final_record.ended_at_ms, Some(0));
            assert!(final_record.has_nullifier(&ended.nullifier));
            assert!(end.execute(&host, stx).is_err());
            assert!(
                CreateKaigi {
                    call: template,
                    commitment: Some(created.commitment),
                    nullifier: Some(created.nullifier),
                    roster_root: Some(created.root),
                    proof: Some(created.proof)
                }
                .execute(&host, stx)
                .is_err()
            );
            assert_eq!(load_call_record(stx, &call), final_record);
            assert!(ensure_kaigi_domain_can_unregister(stx, &domain).is_err());
        });
    }
    #[test]
    fn private_create_requires_every_artifact_and_has_no_signature_only_path() {
        let (domain, host, _) = sample_ids();
        let call = KaigiId::new(domain.clone(), "private-required".parse().unwrap());
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
            let empty = KaigiRecord::from_new(&template, 0);
            let artifacts = authorization_fixture_v1(
                stx,
                &empty,
                &host,
                0,
                KaigiAuthorizationActionV1::HostCreate,
                77,
            );
            for mask in 0_u8..15 {
                let error = CreateKaigi {
                    call: template.clone(),
                    commitment: (mask & 1 != 0).then_some(artifacts.commitment),
                    nullifier: (mask & 2 != 0).then_some(artifacts.nullifier),
                    roster_root: (mask & 4 != 0).then_some(artifacts.root),
                    proof: (mask & 8 != 0).then(|| artifacts.proof.clone()),
                }
                .execute(&host, stx)
                .expect_err("incomplete private host authorization");
                assert!(format!("{error:?}").contains("requires"));
                assert!(
                    !stx.world
                        .domain(&domain)
                        .unwrap()
                        .metadata()
                        .contains(&metadata_key(&call).unwrap())
                );
            }
            CreateKaigi {
                call: template,
                commitment: Some(artifacts.commitment),
                nullifier: Some(artifacts.nullifier),
                roster_root: Some(artifacts.root),
                proof: Some(artifacts.proof),
            }
            .execute(&host, stx)
            .unwrap();
            assert!(
                EndKaigi {
                    call_id: call.clone(),
                    ended_at_ms: None,
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None
                }
                .execute(&host, stx)
                .is_err()
            );
            assert_eq!(load_call_record(stx, &call).status, KaigiStatus::Active);
        });
    }
    #[test]
    fn host_can_update_relay_manifest() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("manifest-update").unwrap());
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            stx.world.take_external_events();
            CreateKaigi {
                call: NewKaigi::with_defaults(call.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            stx.world.take_external_events();
            let manifest = sample_manifest();
            for hop in &manifest.hops {
                let relay_domain: DomainId =
                    DomainId::try_new("relay", "universal").expect("relay domain");
                if stx.world.domain(&relay_domain).is_err() {
                    Register::domain(Domain::new(relay_domain.clone()))
                        .execute(&ALICE_ID, stx)
                        .expect("register relay domain");
                }
                Register::account(Account::new(hop.relay_id.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register relay account");
                add_relay_to_allowlist(stx, &relay_domain, &hop.relay_id);
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: hop.relay_id.clone(),
                        hpke_public_key: hop.hpke_public_key.clone(),
                        bandwidth_class: 1,
                    },
                }
                .execute(&hop.relay_id, stx)
                .expect("register relay");
                stx.world.take_external_events();
            }
            SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(manifest.clone()),
            }
            .execute(&host, stx)
            .expect("set manifest");
            let events = stx.world.take_external_events();
            let summary = extract_manifest_summary(&events).expect("manifest summary event");
            assert_eq!(summary.call, call);
            assert_eq!(summary.hop_count, 3);
            assert_eq!(summary.expiry_ms, 42);
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            let domain = stx.world.domain(&call.domain_id).expect("domain");
            let record: KaigiRecord = domain
                .metadata()
                .get(&key)
                .expect("record metadata")
                .clone()
                .try_into_any_norito()
                .expect("deserialize metadata");
            let stored_manifest = record.relay_manifest.expect("stored relay manifest");
            assert_eq!(stored_manifest.expiry_ms, manifest.expiry_ms);
            assert_eq!(stored_manifest.hops.len(), manifest.hops.len());
            for (stored_hop, expected_hop) in stored_manifest.hops.iter().zip(&manifest.hops) {
                assert_eq!(
                    stored_hop.relay_id.subject_id(),
                    expected_hop.relay_id.subject_id()
                );
                assert_eq!(stored_hop.hpke_public_key, expected_hop.hpke_public_key);
                assert_eq!(stored_hop.weight, expected_hop.weight);
            }
        });
    }
    #[test]
    fn non_host_cannot_update_relay_manifest() {
        let (domain, host, participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("manifest-authz").unwrap());
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            Register::account(Account::new(participant.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register participant");
            stx.world.take_external_events();
            CreateKaigi {
                call: NewKaigi::with_defaults(call.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            stx.world.take_external_events();
            let err = SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(sample_manifest()),
            }
            .execute(&participant, stx)
            .expect_err("non-host update rejected");
            match err {
                Error::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
                    assert_eq!(msg, "only the host may update the Kaigi relay manifest");
                }
                other => panic!("unexpected error variant {other:?}"),
            }
        });
    }
    #[test]
    fn relay_registration_enforces_allowlist() {
        let (domain, host, _) = sample_ids();
        let (relay_id, _) = gen_account_in(domain.name());
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            seed_relay_primary_alias_for_testing(stx, &domain, &relay_id);
            stx.world.take_external_events();
            let allowlist_key = kaigi_relay_allowlist_key().expect("allowlist key");
            let allowlist = KaigiRelayAllowlist::default();
            let allowlist_json = Json::try_new(allowlist).expect("serialize allowlist");
            stx.world
                .domain_mut(&domain)
                .expect("domain exists")
                .metadata_mut()
                .insert(allowlist_key, allowlist_json);
            let registration = KaigiRelayRegistration {
                relay_id: relay_id.clone(),
                hpke_public_key: vec![0xAA],
                bandwidth_class: 1,
            };
            let result = RegisterKaigiRelay {
                relay: registration,
            }
            .execute(&relay_id, stx);
            assert!(
                matches!(result, Err(Error::InvalidParameter(_))),
                "registration should fail when relay is not allowlisted"
            );
        });
    }
    #[test]
    fn relay_registration_rejects_allowlist_only_domain_selection_without_mutation() {
        let domain = DomainId::try_new("relay-home", "universal").expect("domain id");
        let (relay_id, _) = gen_account_in("relay-home");
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            let allowlist_key = kaigi_relay_allowlist_key().expect("allowlist key");
            let mut allowlist = KaigiRelayAllowlist::default();
            allowlist.allowed_relays.insert(relay_id.clone());
            stx.world
                .domain_mut(&domain)
                .expect("domain exists")
                .metadata_mut()
                .insert(
                    allowlist_key,
                    Json::try_new(allowlist).expect("serialize allowlist"),
                );
            stx.world.take_external_events();

            let error = RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: relay_id.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                },
            }
            .execute(&relay_id, stx)
            .expect_err("an allowlist must not choose an aliasless relay's home domain");
            assert_smart_contract_error(error, "domain-qualified primary alias");
            let registration_key = kaigi_relay_metadata_key(&relay_id).expect("registration key");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain exists")
                    .metadata()
                    .get(&registration_key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn unrelated_malformed_allowlist_cannot_block_relay_registration() {
        let home = DomainId::try_new("relay-home", "universal").expect("home domain");
        let unrelated = DomainId::try_new("unrelated", "universal").expect("unrelated domain");
        let (relay_id, _) = gen_account_in("relay-home");
        with_state_transaction(|stx| {
            for domain in [&home, &unrelated] {
                Register::domain(Domain::new(domain.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register domain");
            }
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            add_relay_to_allowlist(stx, &home, &relay_id);
            stx.world
                .domain_mut(&unrelated)
                .expect("unrelated domain exists")
                .metadata_mut()
                .insert(
                    kaigi_relay_allowlist_key().expect("allowlist key"),
                    Json::try_new("not a Kaigi relay allowlist").expect("serialize invalid value"),
                );
            stx.world.take_external_events();

            RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: relay_id.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                },
            }
            .execute(&relay_id, stx)
            .expect("only the relay's authenticated home-domain allowlist is relevant");
            assert!(
                stx.world
                    .domain(&home)
                    .expect("home domain exists")
                    .metadata()
                    .contains(&kaigi_relay_metadata_key(&relay_id).expect("registration key"))
            );
        });
    }
    #[test]
    fn registered_relay_primary_alias_domain_is_pinned() {
        let home = DomainId::try_new("relay-home", "universal").expect("home domain");
        let other = DomainId::try_new("other-home", "universal").expect("other domain");
        let (relay_id, _) = gen_account_in("relay-home");
        with_state_transaction(|stx| {
            for domain in [&home, &other] {
                Register::domain(Domain::new(domain.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register domain");
            }
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            add_relay_to_allowlist(stx, &home, &relay_id);
            RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: relay_id.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                },
            }
            .execute(&relay_id, stx)
            .expect("register relay");

            ensure_kaigi_relay_home_change_allowed(stx, &relay_id, &home, Some(&home))
                .expect("another primary alias in the same domain preserves relay storage");
            let error = ensure_kaigi_relay_home_change_allowed(stx, &relay_id, &home, Some(&other))
                .expect_err("registered relay state must not be stranded in its old domain");
            assert_smart_contract_error(error, "primary alias domain is pinned");
            let error = ensure_kaigi_relay_home_change_allowed(stx, &relay_id, &home, None)
                .expect_err("registered relay must not clear its domain-qualified primary alias");
            assert_smart_contract_error(error, "primary alias domain is pinned");
        });
    }
    #[test]
    fn retained_relay_feedback_alone_pins_primary_alias_domain() {
        let home = DomainId::try_new("relay-home", "universal").expect("home domain");
        let other = DomainId::try_new("other-home", "universal").expect("other domain");
        let (relay_id, _) = gen_account_in("relay-home");
        with_seeded_kaigi_state_transaction(&home, std::slice::from_ref(&relay_id), |stx| {
            let feedback = KaigiRelayFeedback {
                call: KaigiId::new(
                    home.clone(),
                    Name::from_str("retained-feedback").expect("call name"),
                ),
                relay_id: relay_id.clone(),
                reported_by: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 1,
                notes: None,
            };
            let key = kaigi_relay_feedback_key(&relay_id).expect("feedback key");
            stx.world
                .domain_mut(&home)
                .expect("home domain")
                .metadata_mut()
                .insert(
                    key.clone(),
                    Json::try_new(feedback).expect("serialize feedback"),
                );
            seed_kaigi_account_dependency_for_testing(
                stx,
                &relay_id,
                (KAIGI_DEPENDENCY_RELAY_FEEDBACK, home.clone(), key),
            );

            let error = ensure_kaigi_relay_home_change_allowed(stx, &relay_id, &home, Some(&other))
                .expect_err("retained feedback must pin relay storage even without a descriptor");
            assert_smart_contract_error(error, "primary alias domain is pinned");
        });
    }
    #[test]
    fn corrupt_retained_relay_keys_fail_closed_for_alias_move_and_unregister() {
        let home = DomainId::try_new("relay-home", "universal").expect("home domain");
        let other = DomainId::try_new("other-home", "universal").expect("other domain");
        let (key_relay, _) = gen_account_in("relay-home");
        let (payload_relay, _) = gen_account_in("relay-home");
        with_seeded_kaigi_state_transaction(
            &home,
            &[key_relay.clone(), payload_relay.clone()],
            |stx| {
                let descriptor_key = kaigi_relay_metadata_key(&key_relay).expect("descriptor key");
                let descriptor = KaigiRelayRegistration {
                    relay_id: payload_relay.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                };
                stx.world
                    .domain_mut(&home)
                    .expect("home domain")
                    .metadata_mut()
                    .insert(
                        descriptor_key.clone(),
                        Json::try_new(descriptor).expect("serialize descriptor"),
                    );
                let descriptor_dependency = (
                    KAIGI_DEPENDENCY_RELAY_REGISTRATION,
                    home.clone(),
                    descriptor_key.clone(),
                );
                seed_kaigi_account_dependency_for_testing(
                    stx,
                    &key_relay,
                    descriptor_dependency.clone(),
                );
                for error in [
                    ensure_kaigi_relay_home_change_allowed(stx, &key_relay, &home, Some(&other))
                        .expect_err("corrupt descriptor key must reject alias movement"),
                    ensure_kaigi_account_can_unregister(stx, &key_relay)
                        .expect_err("corrupt descriptor key must reject account removal"),
                ] {
                    assert_invariant_error(error, "registration key does not match its relay ID");
                }
                stx.world
                    .domain_mut(&home)
                    .expect("home domain")
                    .metadata_mut()
                    .remove(&descriptor_key);
                remove_kaigi_account_dependency_for_testing(
                    stx,
                    &key_relay,
                    &descriptor_dependency,
                );

                let feedback_key = kaigi_relay_feedback_key(&key_relay).expect("feedback key");
                let feedback = KaigiRelayFeedback {
                    call: KaigiId::new(
                        home.clone(),
                        Name::from_str("corrupt-feedback").expect("call name"),
                    ),
                    relay_id: payload_relay.clone(),
                    reported_by: payload_relay.clone(),
                    status: KaigiRelayHealthStatus::Healthy,
                    reported_at_ms: 1,
                    notes: None,
                };
                stx.world
                    .domain_mut(&home)
                    .expect("home domain")
                    .metadata_mut()
                    .insert(
                        feedback_key.clone(),
                        Json::try_new(feedback.clone()).expect("serialize feedback"),
                    );
                let feedback_dependency = (
                    KAIGI_DEPENDENCY_RELAY_FEEDBACK,
                    home.clone(),
                    feedback_key.clone(),
                );
                seed_kaigi_account_dependency_for_testing(
                    stx,
                    &key_relay,
                    feedback_dependency.clone(),
                );
                for error in [
                    ensure_kaigi_relay_home_change_allowed(stx, &key_relay, &home, Some(&other))
                        .expect_err("corrupt feedback key must reject alias movement"),
                    ensure_kaigi_account_can_unregister(stx, &key_relay)
                        .expect_err("corrupt feedback key must reject account removal"),
                ] {
                    assert_invariant_error(error, "feedback key does not match its relay ID");
                }
                stx.world
                    .domain_mut(&home)
                    .expect("home domain")
                    .metadata_mut()
                    .remove(&feedback_key);
                remove_kaigi_account_dependency_for_testing(stx, &key_relay, &feedback_dependency);

                let correct_feedback_key =
                    kaigi_relay_feedback_key(&payload_relay).expect("correct feedback key");
                stx.world
                    .domain_mut(&home)
                    .expect("home domain")
                    .metadata_mut()
                    .insert(
                        correct_feedback_key.clone(),
                        Json::try_new(feedback).expect("serialize feedback"),
                    );
                seed_kaigi_account_dependency_for_testing(
                    stx,
                    &key_relay,
                    (
                        KAIGI_DEPENDENCY_RELAY_FEEDBACK,
                        home.clone(),
                        correct_feedback_key,
                    ),
                );
                for error in [
                    ensure_kaigi_relay_home_change_allowed(stx, &key_relay, &home, Some(&other))
                        .expect_err("wrong-account feedback index must reject alias movement"),
                    ensure_kaigi_account_can_unregister(stx, &key_relay)
                        .expect_err("wrong-account feedback index must reject account removal"),
                ] {
                    assert_invariant_error(error, "indexed under the wrong account");
                }
            },
        );
    }
    #[test]
    fn relay_home_change_validates_corrupt_relay_locator_before_domain_filtering() {
        let home = DomainId::try_new("relay-home", "universal").expect("home domain");
        let unrelated =
            DomainId::try_new("unrelated-relay-home", "universal").expect("unrelated domain");
        let (relay_id, _) = gen_account_in("relay-home");
        with_state_transaction(|stx| {
            for domain in [&home, &unrelated] {
                Register::domain(Domain::new(domain.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register domain");
            }
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            let missing_key = kaigi_relay_feedback_key(&relay_id).expect("feedback key");
            seed_kaigi_account_dependency_for_testing(
                stx,
                &relay_id,
                (
                    KAIGI_DEPENDENCY_RELAY_FEEDBACK,
                    unrelated.clone(),
                    missing_key,
                ),
            );

            let error = ensure_kaigi_relay_home_change_allowed(stx, &relay_id, &home, None)
                .expect_err("a corrupt out-of-domain relay locator must fail closed");
            assert_invariant_error(error, "references missing metadata");
        });
    }
    #[test]
    fn retired_relay_allowlist_entry_authorizes_only_the_active_successor_id() {
        let home = DomainId::try_new("relay-home", "universal").expect("home domain");
        let (retired_relay, _) = gen_account_in("relay-home");
        let (active_relay, _) = gen_account_in("relay-home");
        with_state_transaction(|stx| {
            Register::domain(Domain::new(home.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(active_relay.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register active relay account");
            seed_active_account_id_rekey_lineage(
                stx,
                "retired-relay-lineage",
                &retired_relay,
                &active_relay,
            );
            seed_relay_primary_alias_for_testing(stx, &home, &active_relay);
            let mut allowlist = KaigiRelayAllowlist::default();
            allowlist.allowed_relays.insert(retired_relay.clone());
            stx.world
                .domain_mut(&home)
                .expect("home domain exists")
                .metadata_mut()
                .insert(
                    kaigi_relay_allowlist_key().expect("allowlist key"),
                    Json::try_new(allowlist).expect("serialize allowlist"),
                );
            stx.world.take_external_events();

            let error = RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: retired_relay.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                },
            }
            .execute(&active_relay, stx)
            .expect_err("the successor must not write a descriptor under the retired ID");
            assert_smart_contract_error(error, "only the relay account");
            assert!(stx.world.take_external_events().is_empty());

            RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: active_relay.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                },
            }
            .execute(&active_relay, stx)
            .expect("an explicit rekey successor inherits relay governance membership");
            assert!(
                stx.world
                    .domain(&home)
                    .expect("home domain exists")
                    .metadata()
                    .contains(&kaigi_relay_metadata_key(&active_relay).expect("registration key"))
            );
        });
    }
    #[test]
    fn call_feedback_does_not_override_manifest_governance() {
        let (domain, host, _) = sample_ids();
        let (relay_a, _) = gen_account_in(domain.name());
        let (relay_b, _) = gen_account_in(domain.name());
        let (relay_c, _) = gen_account_in(domain.name());
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            for relay in [&relay_a, &relay_b, &relay_c] {
                Register::account(Account::new(relay.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register relay account");
                seed_relay_primary_alias_for_testing(stx, &domain, relay);
            }
            stx.world.take_external_events();
            let allowlist_key = kaigi_relay_allowlist_key().expect("allowlist key");
            let mut allowlist = KaigiRelayAllowlist::default();
            allowlist
                .allowed_relays
                .extend([relay_a.clone(), relay_b.clone(), relay_c.clone()]);
            let allowlist_json = Json::try_new(allowlist).expect("serialize allowlist");
            stx.world
                .domain_mut(&domain)
                .expect("domain exists")
                .metadata_mut()
                .insert(allowlist_key, allowlist_json);
            let registrations = [
                (relay_a.clone(), vec![1, 2, 3]),
                (relay_b.clone(), vec![4, 5, 6]),
                (relay_c.clone(), vec![7, 8, 9]),
            ];
            for (relay, hpke_key) in &registrations {
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: relay.clone(),
                        hpke_public_key: hpke_key.clone(),
                        bandwidth_class: 1,
                    },
                }
                .execute(relay, stx)
                .expect("register relay");
            }
            stx.world.take_external_events();
            let call = KaigiId::new(
                domain.clone(),
                Name::from_str("relay-outage").expect("call name"),
            );
            CreateKaigi {
                call: NewKaigi::with_defaults(call.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            stx.world.take_external_events();
            let feedback = KaigiRelayFeedback {
                relay_id: relay_a.clone(),
                call: call.clone(),
                reported_by: host.clone(),
                status: KaigiRelayHealthStatus::Unavailable,
                reported_at_ms: 7,
                notes: Some("offline".to_owned()),
            };
            store_relay_feedback(stx, &feedback).expect("store feedback");
            stx.world.take_external_events();
            let manifest = KaigiRelayManifest {
                hops: vec![
                    KaigiRelayHop {
                        relay_id: relay_a.clone(),
                        hpke_public_key: vec![1, 2, 3],
                        weight: 1,
                    },
                    KaigiRelayHop {
                        relay_id: relay_b.clone(),
                        hpke_public_key: vec![4, 5, 6],
                        weight: 1,
                    },
                    KaigiRelayHop {
                        relay_id: relay_c.clone(),
                        hpke_public_key: vec![7, 8, 9],
                        weight: 1,
                    },
                ],
                expiry_ms: 100,
            };
            SetKaigiRelayManifest {
                call_id: call,
                relay_manifest: Some(manifest),
            }
            .execute(&host, stx)
            .expect("call-scoped health feedback must not become a global manifest-admission veto");
            assert_eq!(
                load_relay_feedback(stx, &relay_a)
                    .expect("load feedback")
                    .expect("stored feedback"),
                feedback
            );
        });
    }
    #[test]
    fn host_can_clear_relay_manifest() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("manifest-clear").unwrap());
        let manifest = sample_manifest();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            stx.world.take_external_events();
            SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: None,
            }
            .execute(&host, stx)
            .expect("clear manifest");
            let events = stx.world.take_external_events();
            let summary = extract_manifest_summary(&events).expect("manifest summary event");
            assert_eq!(summary.call, call);
            assert_eq!(summary.hop_count, 0);
            assert_eq!(summary.expiry_ms, 0);
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            let domain = stx.world.domain(&call.domain_id).expect("domain");
            let record: KaigiRecord = domain
                .metadata()
                .get(&key)
                .expect("record metadata")
                .clone()
                .try_into_any_norito()
                .expect("deserialize metadata");
            assert!(record.relay_manifest.is_none());
        });
    }
    #[test]
    fn unchanged_relay_manifest_update_is_event_free() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("manifest-idempotent").unwrap(),
        );
        let manifest = sample_manifest();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create Kaigi with relay manifest");
            stx.world.take_external_events();

            SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(manifest.clone()),
            }
            .execute(&host, stx)
            .expect("repeat identical manifest");
            assert!(
                stx.world.take_external_events().is_empty(),
                "an identical manifest must not emit metadata or summary events"
            );

            SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: None,
            }
            .execute(&host, stx)
            .expect("clear manifest");
            assert!(
                extract_manifest_summary(&stx.world.take_external_events()).is_some(),
                "the first clear must emit a manifest summary"
            );

            SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: None,
            }
            .execute(&host, stx)
            .expect("repeat clear on an empty manifest");
            assert!(
                stx.world.take_external_events().is_empty(),
                "clearing an already-empty manifest must not emit events"
            );
        });
    }
    #[test]
    fn relay_registration_persists_metadata_and_emits_summary() {
        let (relay_id, _relay_account) = gen_account_in("relay");
        let domain_id = DomainId::try_new("relay", "universal").expect("domain id");
        let registration = KaigiRelayRegistration {
            relay_id: relay_id.clone(),
            hpke_public_key: vec![0x10, 0x20, 0x30],
            bandwidth_class: 5,
        };
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            add_relay_to_allowlist(stx, &domain_id, &relay_id);
            stx.world.take_external_events();
            let oversized_error = RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: relay_id.clone(),
                    hpke_public_key: vec![0xA5; KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 + 1],
                    bandwidth_class: 5,
                },
            }
            .execute(&relay_id, stx)
            .expect_err("oversized relay key must fail before persistence or event emission");
            assert_smart_contract_error(oversized_error, "must not exceed 4096 bytes");
            let key = kaigi_relay_metadata_key(&relay_id).expect("metadata key");
            assert!(
                stx.world
                    .domain(&domain_id)
                    .expect("domain lookup")
                    .metadata()
                    .get(&key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
            RegisterKaigiRelay {
                relay: registration.clone(),
            }
            .execute(&relay_id, stx)
            .expect("register relay");
            let events = stx.world.take_external_events();
            assert_eq!(events.len(), 1, "full relay metadata must remain internal");
            let summary =
                extract_registration_summary(&events).expect("relay registration summary event");
            assert_eq!(summary.relay().subject_id(), relay_id.subject_id());
            assert_eq!(*summary.bandwidth_class(), 5);
            let domain = stx.world.domain(&domain_id).expect("domain lookup");
            let stored = domain
                .metadata()
                .get(&key)
                .cloned()
                .expect("relay metadata");
            let decoded: KaigiRelayRegistration = stored
                .try_into_any_norito()
                .expect("decode relay registration");
            assert_eq!(
                decoded.relay_id.subject_id(),
                registration.relay_id.subject_id()
            );
            assert_eq!(decoded.hpke_public_key, registration.hpke_public_key);
            assert_eq!(decoded.bandwidth_class, registration.bandwidth_class);
            assert_eq!(
                stx.world.kaigi_relay_registry.get(&relay_id),
                Some(&domain_id)
            );

            stx.world
                .domain_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    kaigi_relay_allowlist_key().expect("allowlist key"),
                    Json::try_new(KaigiRelayAllowlist::default())
                        .expect("serialize empty allowlist"),
                );
            let internal_len = stx.world.internal_event_buf.len();
            RegisterKaigiRelay {
                relay: registration.clone(),
            }
            .execute(&relay_id, stx)
            .expect("identical relay registration is an idempotent lookup even after delisting");
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(stx.world.internal_event_buf.len(), internal_len);

            add_relay_to_allowlist(stx, &domain_id, &relay_id);
            let mut rotated = registration.clone();
            rotated.bandwidth_class = 6;
            RegisterKaigiRelay {
                relay: rotated.clone(),
            }
            .execute(&relay_id, stx)
            .expect("changed relay descriptor updates in place");
            let events = stx.world.take_external_events();
            assert_eq!(events.len(), 1, "descriptor updates expose only a summary");
            assert_eq!(
                *extract_registration_summary(&events)
                    .expect("updated registration summary")
                    .bandwidth_class(),
                6
            );
            assert_eq!(
                load_relay_registration(stx, &domain_id, &relay_id),
                Some(rotated)
            );
        });
    }
    #[test]
    fn relay_registry_cap_rejects_new_entries_but_allows_update_and_retirement() {
        let domain_id = DomainId::try_new("relay-cap", "universal").expect("domain id");
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay domain");
            let mut relay_ids = Vec::with_capacity(KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1 + 1);
            for index in 0..=KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1 {
                let (relay_id, _) = gen_account_in("relay-cap");
                Register::account(Account::new(relay_id.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register relay account");
                seed_relay_primary_alias_for_testing(stx, &domain_id, &relay_id);
                if index < KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1 {
                    let registration = KaigiRelayRegistration {
                        relay_id: relay_id.clone(),
                        hpke_public_key: vec![u8::try_from(index % 251).expect("bounded byte") + 1],
                        bandwidth_class: 1,
                    };
                    let registration_key =
                        kaigi_relay_metadata_key(&relay_id).expect("registration key");
                    stx.world
                        .domain_mut(&domain_id)
                        .expect("relay domain")
                        .metadata_mut()
                        .insert(
                            registration_key.clone(),
                            Json::try_new(registration).expect("serialize registration"),
                        );
                    stx.world
                        .kaigi_relay_registry
                        .insert(relay_id.clone(), domain_id.clone());
                    seed_kaigi_account_dependency_for_testing(
                        stx,
                        &relay_id,
                        (
                            KAIGI_DEPENDENCY_RELAY_REGISTRATION,
                            domain_id.clone(),
                            registration_key,
                        ),
                    );
                }
                relay_ids.push(relay_id);
            }
            let existing = relay_ids[0].clone();
            let new_relay = relay_ids.last().expect("extra relay account").clone();
            add_relay_to_allowlist(stx, &domain_id, &existing);
            add_relay_to_allowlist(stx, &domain_id, &new_relay);
            stx.world.take_external_events();

            let rotated = KaigiRelayRegistration {
                relay_id: existing.clone(),
                hpke_public_key: vec![0xAA, 0xBB],
                bandwidth_class: 2,
            };
            RegisterKaigiRelay {
                relay: rotated.clone(),
            }
            .execute(&existing, stx)
            .expect("an existing descriptor may rotate at the registry cap");
            assert_eq!(
                load_relay_registration(stx, &domain_id, &existing),
                Some(rotated)
            );
            stx.world.take_external_events();

            let rejected = KaigiRelayRegistration {
                relay_id: new_relay.clone(),
                hpke_public_key: vec![0xCC],
                bandwidth_class: 1,
            };
            let error = RegisterKaigiRelay {
                relay: rejected.clone(),
            }
            .execute(&new_relay, stx)
            .expect_err("a new descriptor must be rejected at the registry cap");
            assert_smart_contract_error(error, "500-entry limit");
            assert_eq!(load_relay_registration(stx, &domain_id, &new_relay), None);
            assert!(stx.world.take_external_events().is_empty());

            let rejected_key = kaigi_relay_metadata_key(&new_relay).expect("registration key");
            stx.world
                .domain_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    rejected_key.clone(),
                    Json::try_new(rejected)
                        .expect("serialize deliberately invalid over-cap registration"),
                );
            stx.world
                .kaigi_relay_registry
                .insert(new_relay.clone(), domain_id.clone());
            seed_kaigi_account_dependency_for_testing(
                stx,
                &new_relay,
                (
                    KAIGI_DEPENDENCY_RELAY_REGISTRATION,
                    domain_id.clone(),
                    rejected_key,
                ),
            );
            let error = collect_kaigi_relay_registry(&stx.world)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("final V1 restore must reject over-cap registry");
            assert_smart_contract_error(error, "final V1 capacity");
            assert_eq!(
                validated_kaigi_relay_registry_count(stx).expect("validate over-cap registry"),
                KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1 + 1
            );
            UnregisterKaigiRelay {
                relay_id: existing.clone(),
            }
            .execute(&existing, stx)
            .expect("retirement must remain available above the cap");
            assert_eq!(
                validated_kaigi_relay_registry_count(stx).expect("validate repaired registry"),
                KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1
            );
        });
    }
    #[test]
    fn relay_registry_rebuild_fails_closed_on_malformed_row() {
        let domain_id = DomainId::try_new("relay-corrupt", "universal").expect("domain id");
        let (corrupt_key_owner, _) = gen_account_in("relay-corrupt");
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay domain");
            Register::account(Account::new(corrupt_key_owner.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            seed_relay_primary_alias_for_testing(stx, &domain_id, &corrupt_key_owner);
            let corrupt_key =
                kaigi_relay_metadata_key(&corrupt_key_owner).expect("corrupt registration key");
            stx.world
                .domain_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    corrupt_key,
                    Json::try_new("not a relay registration").expect("serialize corrupt row"),
                );
            let error = collect_kaigi_relay_registry(&stx.world)
                .expect_err("a malformed registry row must fail closed during rebuild");
            assert_invariant_error(error, "malformed Kaigi relay registration");
        });
    }
    #[test]
    fn relay_registry_rebuild_rejects_over_limit_governance_allowlist() {
        let domain_id = DomainId::try_new("relay-allowlist-cap", "universal").expect("domain id");
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay domain");
            let mut allowlist = KaigiRelayAllowlist::default();
            for _ in 0..=KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1 {
                let (relay_id, _) = gen_account_in("relay-allowlist-cap");
                allowlist.allowed_relays.insert(relay_id);
            }
            stx.world
                .domain_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    kaigi_relay_allowlist_key().expect("allowlist key"),
                    Json::try_new(allowlist).expect("serialize over-limit allowlist"),
                );

            let load_error = load_allowlist(stx, &domain_id)
                .expect_err("runtime allowlist reads must reject retained over-limit state");
            assert_invariant_error(load_error, "500-entry limit");
            let error = collect_kaigi_relay_registry(&stx.world)
                .expect_err("snapshot rebuild must reject an over-limit allowlist");
            assert_invariant_error(error, "500-entry limit");
        });
    }
    #[test]
    fn relay_registry_rebuild_rejects_over_limit_allowlist_in_undo_layer() {
        let domain_id =
            DomainId::try_new("relay-allowlist-undo-cap", "universal").expect("domain id");
        let allowlist_key = kaigi_relay_allowlist_key().expect("allowlist key");
        let mut allowlist = KaigiRelayAllowlist::default();
        for _ in 0..=KAIGI_RELAY_ALLOWLIST_MAX_ENTRIES_V1 {
            let (relay_id, _) = gen_account_in("relay-allowlist-undo-cap");
            allowlist.allowed_relays.insert(relay_id);
        }
        let mut world = World::with(
            [Domain::new(domain_id.clone()).build(&ALICE_ID)],
            std::iter::empty::<Account>(),
            std::iter::empty::<AssetDefinition>(),
        );
        {
            let mut domains = world.domains.block();
            domains
                .get_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    allowlist_key.clone(),
                    Json::try_new(allowlist).expect("serialize over-limit allowlist"),
                );
            domains.commit();
        }
        {
            let mut domains = world.domains.block();
            domains
                .get_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .remove(&allowlist_key);
            domains.commit();
        }
        let authoritative_before =
            norito::json::to_json(&world.domains).expect("serialize domain MV state");
        let error = rebuild_kaigi_relay_registry(&mut world)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("rebuild must validate the latest block's undo layer");
        assert!(
            error.contains("500-entry limit"),
            "unexpected error: {error}"
        );
        assert_eq!(
            norito::json::to_json(&world.domains).expect("serialize domain MV state after failure"),
            authoritative_before,
            "failed undo-layer validation must preserve authoritative MV state"
        );
    }
    #[test]
    fn account_dependency_rebuild_rejects_invalid_record_in_undo_layer() {
        let domain_id = DomainId::try_new("kaigi-record-undo-cap", "universal").expect("domain id");
        let (host, _) = gen_account_in("kaigi-record-undo-cap");
        let call = KaigiId::new(
            domain_id.clone(),
            Name::from_str("invalid-before-revert").expect("call name"),
        );
        let mut record =
            KaigiRecord::from_new(&NewKaigi::with_defaults(call.clone(), host.clone()), 0);
        record.ended_at_ms = Some(0);
        let record_key = kaigi_metadata_key(&call.call_name).expect("Kaigi metadata key");
        let mut world = World::with(
            [Domain::new(domain_id.clone()).build(&ALICE_ID)],
            [Account::new(host).build(&ALICE_ID)],
            std::iter::empty::<AssetDefinition>(),
        );
        {
            let mut domains = world.domains.block();
            domains
                .get_mut(&domain_id)
                .expect("Kaigi domain")
                .metadata_mut()
                .insert(
                    record_key.clone(),
                    Json::try_new(record).expect("serialize invalid retained record"),
                );
            domains.commit();
        }
        {
            let mut domains = world.domains.block();
            domains
                .get_mut(&domain_id)
                .expect("Kaigi domain")
                .metadata_mut()
                .remove(&record_key);
            domains.commit();
        }
        let authoritative_before =
            norito::json::to_json(&world.domains).expect("serialize domain MV state");
        let error = rebuild_kaigi_account_dependencies(&mut world)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("rebuild must validate invalid records in the latest undo layer");
        assert!(
            error.contains("active Kaigi record must not retain an end timestamp"),
            "unexpected error: {error}"
        );
        assert_eq!(
            norito::json::to_json(&world.domains).expect("serialize domain MV state after failure"),
            authoritative_before,
            "failed undo-layer validation must preserve authoritative MV state"
        );
        assert!(world.kaigi_account_dependencies.view().is_empty());
    }
    #[test]
    fn relay_registry_rebuild_rejects_duplicate_relay_rows() {
        let first = DomainId::try_new("relay-first", "universal").expect("first domain id");
        let second = DomainId::try_new("relay-second", "universal").expect("second domain id");
        let (relay_id, _) = gen_account_in("relay-first");
        with_state_transaction(|stx| {
            for domain_id in [&first, &second] {
                Register::domain(Domain::new(domain_id.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register relay domain");
                let registration = KaigiRelayRegistration {
                    relay_id: relay_id.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                };
                stx.world
                    .domain_mut(domain_id)
                    .expect("relay domain")
                    .metadata_mut()
                    .insert(
                        kaigi_relay_metadata_key(&relay_id).expect("registration key"),
                        Json::try_new(registration).expect("serialize registration"),
                    );
            }

            let error = collect_kaigi_relay_registry(&stx.world)
                .expect_err("duplicate relay rows must fail state rebuild");
            assert_invariant_error(error, "duplicate Kaigi relay registration");
        });
    }
    #[test]
    fn retained_call_rebuild_rejects_future_lifecycle_timestamps() {
        let (domain, host, _) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("future-retained-call").expect("call name"),
        );
        let key = kaigi_metadata_key(&call.call_name).expect("call metadata key");
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            let mut record =
                KaigiRecord::from_new(&NewKaigi::with_defaults(call.clone(), host.clone()), 21);
            stx.world
                .domain_mut(&domain)
                .expect("call domain")
                .metadata_mut()
                .insert(
                    key.clone(),
                    Json::try_new(record.clone()).expect("serialize future-created call"),
                );
            let error = collect_kaigi_account_dependencies_at(&stx.world, Some(20))
                .expect_err("future call creation must fail restore");
            assert_invariant_error(
                error,
                "creation timestamp 21 exceeds restored ledger time 20",
            );

            record.created_at_ms = 20;
            record.status = KaigiStatus::Ended;
            record.ended_at_ms = Some(21);
            stx.world
                .domain_mut(&domain)
                .expect("call domain")
                .metadata_mut()
                .insert(
                    key.clone(),
                    Json::try_new(record.clone()).expect("serialize future-ended call"),
                );
            let error = collect_kaigi_account_dependencies_at(&stx.world, Some(20))
                .expect_err("future call end must fail restore");
            assert_invariant_error(error, "end timestamp 21 exceeds restored ledger time 20");

            record.ended_at_ms = Some(20);
            stx.world
                .domain_mut(&domain)
                .expect("call domain")
                .metadata_mut()
                .insert(
                    key.clone(),
                    Json::try_new(record).expect("serialize valid ended call"),
                );
            collect_kaigi_account_dependencies_at(&stx.world, Some(20))
                .expect("call lifecycle timestamps at ledger time remain restorable");
        });
    }
    #[test]
    fn retained_relay_feedback_rebuild_rejects_poisoned_rows() {
        let home = DomainId::try_new("feedback-home", "universal").expect("home domain id");
        let wrong = DomainId::try_new("feedback-wrong", "universal").expect("wrong domain id");
        let (relay_id, _) = gen_account_in("feedback-home");
        let feedback_key =
            kaigi_relay_feedback_key(&relay_id).expect("relay feedback metadata key");
        let call = KaigiId::new(
            home.clone(),
            Name::from_str("restore-feedback").expect("call name"),
        );
        with_state_transaction_at(20, |stx| {
            for domain_id in [&home, &wrong] {
                Register::domain(Domain::new(domain_id.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register feedback domain");
            }
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            add_relay_to_allowlist(stx, &home, &relay_id);
            RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: relay_id.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                },
            }
            .execute(&relay_id, stx)
            .expect("register relay descriptor");

            let mut feedback = KaigiRelayFeedback {
                relay_id: relay_id.clone(),
                call: call.clone(),
                reported_by: ALICE_ID.clone(),
                status: KaigiRelayHealthStatus::Degraded,
                reported_at_ms: 20,
                notes: None,
            };
            let error = ensure_kaigi_json_len(
                KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1 + 1,
                KAIGI_METADATA_VALUE_MAX_JSON_BYTES_V1,
                "stored Kaigi relay feedback",
            )
            .expect_err("retained feedback must remain inside the V1 JSON byte bound");
            assert!(
                error.contains("byte JSON limit"),
                "unexpected error: {error}"
            );

            feedback.notes = None;
            stx.world
                .domain_mut(&wrong)
                .expect("wrong domain")
                .metadata_mut()
                .insert(
                    feedback_key.clone(),
                    Json::try_new(feedback.clone()).expect("serialize wrong-home feedback"),
                );
            let error = collect_kaigi_account_dependencies_at(&stx.world, Some(20))
                .expect_err("wrong-home feedback must fail restore");
            assert_invariant_error(error, "instead of its registered home");
            stx.world
                .domain_mut(&wrong)
                .expect("wrong domain")
                .metadata_mut()
                .remove(&feedback_key);

            feedback.notes = Some("界".repeat(KAIGI_RELAY_HEALTH_NOTES_MAX_CHARS_V1 + 1));
            stx.world
                .domain_mut(&home)
                .expect("home domain")
                .metadata_mut()
                .insert(
                    feedback_key.clone(),
                    Json::try_new(feedback.clone()).expect("serialize overlong notes"),
                );
            let error = collect_kaigi_account_dependencies_at(&stx.world, Some(20))
                .expect_err("overlong retained feedback notes must fail restore");
            assert_invariant_error(error, "character limit");

            feedback.notes = None;
            feedback.reported_at_ms = 21;
            stx.world
                .domain_mut(&home)
                .expect("home domain")
                .metadata_mut()
                .insert(
                    feedback_key.clone(),
                    Json::try_new(feedback.clone()).expect("serialize future feedback"),
                );
            let error = collect_kaigi_account_dependencies_at(&stx.world, Some(20))
                .expect_err("future retained feedback must fail restore");
            assert_invariant_error(error, "exceeds restored ledger time");

            feedback.reported_at_ms = 20;
            stx.world
                .domain_mut(&home)
                .expect("home domain")
                .metadata_mut()
                .insert(
                    feedback_key.clone(),
                    Json::try_new(feedback).expect("serialize valid feedback"),
                );
            let error = collect_kaigi_account_dependencies_at(&stx.world, Some(20))
                .expect_err("feedback without an authoritative call must fail restore");
            assert_invariant_error(error, "references missing call");
        });
    }
    #[test]
    fn relay_registry_rebuild_preserves_latest_block_revert() {
        let domain_id = DomainId::try_new("relay-revert", "universal").expect("domain id");
        let (relay_id, _) = gen_account_in("relay-revert");
        let registration_key = kaigi_relay_metadata_key(&relay_id).expect("relay registration key");
        let mut domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        domain.metadata_mut().insert(
            registration_key.clone(),
            Json::try_new(KaigiRelayRegistration {
                relay_id: relay_id.clone(),
                hpke_public_key: vec![0xAA],
                bandwidth_class: 1,
            })
            .expect("serialize relay registration"),
        );
        let mut world = World::with(
            [domain],
            std::iter::empty::<Account>(),
            std::iter::empty::<AssetDefinition>(),
        );
        {
            let mut domains = world.domains.block();
            domains
                .get_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .remove(&registration_key);
            domains.commit();
        }
        let authoritative_before =
            norito::json::to_json(&world.domains).expect("serialize domain MV state");
        rebuild_kaigi_relay_registry(&mut world).expect("rebuild relay index");
        assert!(world.kaigi_relay_registry.view().is_empty());
        assert_eq!(
            norito::json::to_json(&world.domains).expect("serialize rebuilt domain MV state"),
            authoritative_before,
            "relay index rebuild must preserve authoritative domain MV history"
        );
        let reverted = world.kaigi_relay_registry.block_and_revert();
        assert_eq!(reverted.get(&relay_id), Some(&domain_id));
        reverted.commit();
    }
    #[test]
    fn account_dependency_rebuild_preserves_latest_block_revert() {
        let domain_id = DomainId::try_new("kaigi-revert", "universal").expect("domain id");
        let (host, _) = gen_account_in("kaigi-revert");
        let call = KaigiId::new(
            domain_id.clone(),
            Name::from_str("active-before-revert").expect("call name"),
        );
        let record = KaigiRecord::from_new(&NewKaigi::with_defaults(call.clone(), host.clone()), 0);
        let record_key = kaigi_metadata_key(&call.call_name).expect("Kaigi metadata key");
        let dependency = (
            KAIGI_DEPENDENCY_ACTIVE_CALL,
            domain_id.clone(),
            record_key.clone(),
        );
        let mut domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        domain.metadata_mut().insert(
            record_key.clone(),
            Json::try_new(record).expect("serialize Kaigi record"),
        );
        let mut world = World::with(
            [domain],
            [Account::new(host.clone()).build(&ALICE_ID)],
            std::iter::empty::<AssetDefinition>(),
        );
        assert!(
            world
                .kaigi_account_dependencies
                .view()
                .get(&host)
                .is_some_and(|dependencies| dependencies.contains(&dependency))
        );
        {
            let mut domains = world.domains.block();
            domains
                .get_mut(&domain_id)
                .expect("Kaigi domain")
                .metadata_mut()
                .remove(&record_key);
            domains.commit();
        }
        let authoritative_before =
            norito::json::to_json(&world.domains).expect("serialize domain MV state");
        rebuild_kaigi_account_dependencies(&mut world).expect("rebuild dependency index");
        assert!(world.kaigi_account_dependencies.view().is_empty());
        assert_eq!(
            norito::json::to_json(&world.domains).expect("serialize rebuilt domain MV state"),
            authoritative_before,
            "dependency-index rebuild must preserve authoritative domain MV history"
        );
        let reverted = world.kaigi_account_dependencies.block_and_revert();
        assert!(
            reverted
                .get(&host)
                .is_some_and(|dependencies| dependencies.contains(&dependency))
        );
        reverted.commit();
    }
    #[test]
    fn rebuilt_relay_registry_rejects_mis_homed_metadata() {
        let home = DomainId::try_new("relay-home", "universal").expect("home domain id");
        let wrong = DomainId::try_new("relay-wrong", "universal").expect("wrong domain id");
        let (relay_id, _) = gen_account_in("relay-home");
        with_state_transaction(|stx| {
            for domain_id in [&home, &wrong] {
                Register::domain(Domain::new(domain_id.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register relay domain");
            }
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            seed_relay_primary_alias_for_testing(stx, &home, &relay_id);
            let registration = KaigiRelayRegistration {
                relay_id: relay_id.clone(),
                hpke_public_key: vec![0xAA],
                bandwidth_class: 1,
            };
            stx.world
                .domain_mut(&wrong)
                .expect("wrong domain")
                .metadata_mut()
                .insert(
                    kaigi_relay_metadata_key(&relay_id).expect("registration key"),
                    Json::try_new(registration).expect("serialize registration"),
                );
            let rebuilt =
                collect_kaigi_relay_registry(&stx.world).expect("structurally valid registry");
            for (relay_id, domain_id) in rebuilt {
                stx.world.kaigi_relay_registry.insert(relay_id, domain_id);
            }

            let error = validate_rebuilt_kaigi_relay_registry(&stx.world)
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("mis-homed relay metadata must fail state rebuild");
            assert!(
                error.contains("outside its persisted home domain"),
                "unexpected rebuild error: {error}"
            );
        });
    }
    #[test]
    fn relay_registration_fails_closed_when_metadata_and_index_disagree() {
        let domain_id = DomainId::try_new("relay-index", "universal").expect("domain id");
        let (relay_id, _) = gen_account_in("relay-index");
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay domain");
            Register::account(Account::new(relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register relay account");
            seed_relay_primary_alias_for_testing(stx, &domain_id, &relay_id);
            add_relay_to_allowlist(stx, &domain_id, &relay_id);
            let registration = KaigiRelayRegistration {
                relay_id: relay_id.clone(),
                hpke_public_key: vec![0xAA],
                bandwidth_class: 1,
            };
            stx.world
                .domain_mut(&domain_id)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    kaigi_relay_metadata_key(&relay_id).expect("registration key"),
                    Json::try_new(registration.clone()).expect("serialize registration"),
                );

            let error = RegisterKaigiRelay {
                relay: registration,
            }
            .execute(&relay_id, stx)
            .expect_err("an unindexed metadata row must not pass as an idempotent registration");
            assert_invariant_error(error, "metadata and registry index disagree");
        });
    }
    #[test]
    fn relay_retirement_is_atomic_and_active_manifests_remain_self_contained() {
        let (domain, host, _) = sample_ids();
        let call_id = KaigiId::new(
            domain.clone(),
            Name::from_str("retired-relay").expect("call name"),
        );
        let manifest = sample_manifest();
        let retired_relay = manifest.hops[0].relay_id.clone();
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            register_manifest_relays(stx, &domain, &manifest);
            let registration_dependency = (
                KAIGI_DEPENDENCY_RELAY_REGISTRATION,
                domain.clone(),
                kaigi_relay_metadata_key(&retired_relay).expect("registration key"),
            );
            assert!(
                stx.world
                    .kaigi_account_dependencies
                    .get(&retired_relay)
                    .is_some_and(|dependencies| dependencies.contains(&registration_dependency))
            );
            let mut template = NewKaigi::with_defaults(call_id.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create call with pinned relay manifest");
            let feedback = KaigiRelayFeedback {
                relay_id: retired_relay.clone(),
                call: call_id.clone(),
                reported_by: host.clone(),
                status: KaigiRelayHealthStatus::Degraded,
                reported_at_ms: 0,
                notes: Some("retiring".to_owned()),
            };
            store_relay_feedback(stx, &feedback).expect("seed relay feedback");
            let feedback_dependency = (
                KAIGI_DEPENDENCY_RELAY_FEEDBACK,
                domain.clone(),
                kaigi_relay_feedback_key(&retired_relay).expect("feedback key"),
            );
            assert!(
                stx.world
                    .kaigi_account_dependencies
                    .get(&retired_relay)
                    .is_some_and(|dependencies| dependencies.contains(&feedback_dependency))
            );
            stx.world.take_external_events();
            let internal_len = stx.world.internal_event_buf.len();
            let registration = load_relay_registration(stx, &domain, &retired_relay);
            let call_before_retirement = load_call_record(stx, &call_id);
            let error = UnregisterKaigiRelay {
                relay_id: retired_relay.clone(),
            }
            .execute(&retired_relay, stx)
            .expect_err("an active manifest must retain its registered HPKE route");
            assert_smart_contract_error(error, "active Kaigi");
            assert_eq!(
                load_relay_registration(stx, &domain, &retired_relay),
                registration
            );
            assert_eq!(load_call_record(stx, &call_id), call_before_retirement);
            assert_eq!(
                load_relay_feedback(stx, &retired_relay).unwrap(),
                Some(feedback)
            );
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(stx.world.internal_event_buf.len(), internal_len);

            EndKaigi {
                call_id: call_id.clone(),
                ended_at_ms: None,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("the authenticated host ends the original call");
            assert_eq!(load_call_record(stx, &call_id).status, KaigiStatus::Ended);
            assert_eq!(
                load_call_record(stx, &call_id).relay_manifest,
                Some(manifest.clone())
            );
            stx.world.take_external_events();
            let internal_len = stx.world.internal_event_buf.len();

            UnregisterKaigiRelay {
                relay_id: retired_relay.clone(),
            }
            .execute(&retired_relay, stx)
            .expect("relay may retire after the host ends its active call");
            let events = stx.world.take_external_events();
            assert_eq!(events.len(), 1, "removal metadata must remain internal");
            let summary = extract_unregistration_summary(&events)
                .expect("relay unregistration summary event");
            assert_eq!(summary.relay(), &retired_relay);
            assert_eq!(summary.domain(), &domain);
            assert_eq!(stx.world.internal_event_buf.len(), internal_len + 3);
            assert_eq!(load_relay_registration(stx, &domain, &retired_relay), None);
            assert!(stx.world.kaigi_relay_registry.get(&retired_relay).is_none());
            let remaining_dependencies = stx
                .world
                .kaigi_account_dependencies
                .get(&retired_relay)
                .cloned()
                .unwrap_or_default();
            assert!(!remaining_dependencies.contains(&registration_dependency));
            assert!(!remaining_dependencies.contains(&feedback_dependency));
            assert!(
                !remaining_dependencies
                    .iter()
                    .any(|(kind, _, _)| { *kind == KAIGI_DEPENDENCY_ACTIVE_CALL }),
                "the ended call must release its live relay dependency"
            );
            ensure_kaigi_relay_home_change_allowed(stx, &retired_relay, &domain, None)
                .expect("retained historical manifests do not pin relay metadata home");
            assert_eq!(
                load_relay_feedback(stx, &retired_relay).expect("load removed feedback"),
                None
            );
            assert_eq!(
                load_call_record(stx, &call_id).relay_manifest,
                Some(manifest.clone()),
                "retirement must not rewrite the original historical call's pinned manifest"
            );

            let mut future = NewKaigi::with_defaults(
                KaigiId::new(
                    domain.clone(),
                    Name::from_str("retired-relay-future").unwrap(),
                ),
                host.clone(),
            );
            future.relay_manifest = Some(manifest.clone());
            let error = CreateKaigi {
                call: future,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("retired descriptors must be unavailable to future manifest admission");
            assert_smart_contract_error(error, "not registered");
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn relay_retirement_validates_feedback_before_removing_either_row() {
        let domain_id = DomainId::try_new("relay-atomic", "universal").expect("domain id");
        let (relay_id, _) = gen_account_in("relay-atomic");
        let (other_relay, _) = gen_account_in("relay-atomic");
        with_seeded_kaigi_state_transaction(
            &domain_id,
            &[relay_id.clone(), other_relay.clone()],
            |stx| {
                add_relay_to_allowlist(stx, &domain_id, &relay_id);
                let registration = KaigiRelayRegistration {
                    relay_id: relay_id.clone(),
                    hpke_public_key: vec![0xAA],
                    bandwidth_class: 1,
                };
                RegisterKaigiRelay {
                    relay: registration.clone(),
                }
                .execute(&relay_id, stx)
                .expect("register relay");
                stx.world.take_external_events();
                let error = UnregisterKaigiRelay {
                    relay_id: relay_id.clone(),
                }
                .execute(&other_relay, stx)
                .expect_err("an unrelated account must not retire a relay descriptor");
                assert_smart_contract_error(error, "only the relay account");
                assert_eq!(
                    load_relay_registration(stx, &domain_id, &relay_id),
                    Some(registration.clone())
                );
                assert!(stx.world.take_external_events().is_empty());

                let feedback_key = kaigi_relay_feedback_key(&relay_id).expect("relay feedback key");
                let corrupt_feedback = KaigiRelayFeedback {
                    relay_id: other_relay.clone(),
                    call: KaigiId::new(
                        domain_id.clone(),
                        Name::from_str("corrupt-feedback").expect("call name"),
                    ),
                    reported_by: relay_id.clone(),
                    status: KaigiRelayHealthStatus::Healthy,
                    reported_at_ms: 0,
                    notes: None,
                };
                stx.world
                    .domain_mut(&domain_id)
                    .expect("relay domain")
                    .metadata_mut()
                    .insert(
                        feedback_key.clone(),
                        Json::try_new(corrupt_feedback).expect("serialize corrupt feedback"),
                    );
                stx.world.take_external_events();

                let error = UnregisterKaigiRelay {
                    relay_id: relay_id.clone(),
                }
                .execute(&relay_id, stx)
                .expect_err("corrupt feedback must abort relay retirement");
                assert_invariant_error(error, "feedback identifier does not match");
                assert_eq!(
                    load_relay_registration(stx, &domain_id, &relay_id),
                    Some(registration)
                );
                assert_eq!(
                    stx.world.kaigi_relay_registry.get(&relay_id),
                    Some(&domain_id)
                );
                assert!(
                    stx.world
                        .domain(&domain_id)
                        .expect("relay domain")
                        .metadata()
                        .contains(&feedback_key)
                );
                assert!(stx.world.take_external_events().is_empty());
            },
        );
    }
    #[test]
    fn active_rekey_successor_may_retire_predecessor_relay_descriptor() {
        let domain_id = DomainId::try_new("relay-lineage", "universal").expect("domain id");
        let (retired_relay, _) = gen_account_in("relay-lineage");
        let (active_relay, active_relay_key) = gen_account_in("relay-lineage");
        with_seeded_kaigi_state_transaction(
            &domain_id,
            std::slice::from_ref(&retired_relay),
            |stx| {
                add_relay_to_allowlist(stx, &domain_id, &retired_relay);
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: retired_relay.clone(),
                        hpke_public_key: vec![0xAA],
                        bandwidth_class: 1,
                    },
                }
                .execute(&retired_relay, stx)
                .expect("register predecessor descriptor");
                ReplaceAccountController {
                    account: retired_relay.clone(),
                    new_controller: AccountController::single(
                        active_relay_key.public_key().clone(),
                    ),
                }
                .execute(&retired_relay, stx)
                .expect("replace relay controller");
                assert!(stx.world.account(&retired_relay).is_err());
                assert!(stx.world.account(&active_relay).is_ok());
                stx.world.take_external_events();

                UnregisterKaigiRelay {
                    relay_id: retired_relay.clone(),
                }
                .execute(&active_relay, stx)
                .expect("active canonical successor may retire predecessor descriptor");
                assert_eq!(
                    load_relay_registration(stx, &domain_id, &retired_relay),
                    None
                );
                assert!(
                    extract_unregistration_summary(&stx.world.take_external_events()).is_some()
                );
            },
        );
    }
    #[test]
    fn expired_relay_alias_does_not_block_registry_admission_or_retirement() {
        let domain_id = DomainId::try_new("relay-expired", "universal").expect("domain id");
        let (expired_relay, _) = gen_account_in("relay-expired");
        let (new_relay, _) = gen_account_in("relay-expired");
        with_seeded_kaigi_state_transaction(
            &domain_id,
            &[expired_relay.clone(), new_relay.clone()],
            |stx| {
                add_relay_to_allowlist(stx, &domain_id, &expired_relay);
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: expired_relay.clone(),
                        hpke_public_key: vec![0xAA],
                        bandwidth_class: 1,
                    },
                }
                .execute(&expired_relay, stx)
                .expect("register relay before its alias expires");
                expire_relay_primary_alias_for_testing(stx, &expired_relay);

                add_relay_to_allowlist(stx, &domain_id, &new_relay);
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: new_relay.clone(),
                        hpke_public_key: vec![0xBB],
                        bandwidth_class: 1,
                    },
                }
                .execute(&new_relay, stx)
                .expect("an expired indexed relay must not poison later registry admission");

                UnregisterKaigiRelay {
                    relay_id: expired_relay.clone(),
                }
                .execute(&expired_relay, stx)
                .expect("an expired relay must retain the ability to retire its descriptor");
                assert_eq!(
                    load_relay_registration(stx, &domain_id, &expired_relay),
                    None
                );
                assert_eq!(
                    stx.world.kaigi_relay_registry.get(&new_relay),
                    Some(&domain_id)
                );
            },
        );
    }
    #[test]
    fn manifest_requires_registered_relays() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("manifest-validate").unwrap());
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host account");
            stx.world.take_external_events();
            CreateKaigi {
                call: NewKaigi::with_defaults(call.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            stx.world.take_external_events();
            let manifest = sample_manifest();
            for _hop in &manifest.hops {
                let relay_domain: DomainId =
                    DomainId::try_new("relay", "universal").expect("relay domain");
                if stx.world.domain(&relay_domain).is_err() {
                    Register::domain(Domain::new(relay_domain))
                        .execute(&ALICE_ID, stx)
                        .expect("register relay domain");
                }
            }
            let err = SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(manifest.clone()),
            }
            .execute(&host, stx)
            .expect_err("unregistered relays rejected");
            match err {
                Error::InvalidParameter(InvalidParameterError::SmartContract(msg)) => {
                    assert!(msg.contains("relay"));
                }
                other => panic!("unexpected error variant {other:?}"),
            }
            for hop in &manifest.hops {
                let relay_domain: DomainId =
                    DomainId::try_new("relay", "universal").expect("relay domain");
                if stx.world.domain(&relay_domain).is_err() {
                    Register::domain(Domain::new(relay_domain.clone()))
                        .execute(&ALICE_ID, stx)
                        .expect("register relay domain");
                }
                Register::account(Account::new(hop.relay_id.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register relay account");
                stx.world.take_external_events();
                add_relay_to_allowlist(stx, &relay_domain, &hop.relay_id);
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: hop.relay_id.clone(),
                        hpke_public_key: hop.hpke_public_key.clone(),
                        bandwidth_class: 1,
                    },
                }
                .execute(&hop.relay_id, stx)
                .expect("register relay");
                stx.world.take_external_events();
            }
            SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(manifest.clone()),
            }
            .execute(&host, stx)
            .expect("manifest accepted after registration");
            let events = stx.world.take_external_events();
            let manifest_summary =
                extract_manifest_summary(&events).expect("relay manifest summary event");
            assert_eq!(manifest_summary.call, call);
            assert_eq!(
                manifest_summary.hop_count,
                truncate_len(manifest.hops.len())
            );
        });
    }
    #[test]
    fn manifest_rejects_corrupt_relay_registration_identity_and_bandwidth() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("manifest-corrupt-registration").expect("call name"),
        );
        let manifest = sample_manifest();
        let relay = manifest.hops[0].clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            CreateKaigi {
                call: NewKaigi::with_defaults(call.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            let original_record = load_call_record(stx, &call);
            stx.world.take_external_events();

            let key = kaigi_relay_metadata_key(&relay.relay_id).expect("relay metadata key");
            let corrupt_identity = KaigiRelayRegistration {
                relay_id: manifest.hops[1].relay_id.clone(),
                hpke_public_key: relay.hpke_public_key.clone(),
                bandwidth_class: 1,
            };
            stx.world
                .domain_mut(&domain)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    key.clone(),
                    Json::try_new(corrupt_identity).expect("serialize corrupt registration"),
                );
            let error = SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(manifest.clone()),
            }
            .execute(&host, stx)
            .expect_err("mismatched stored relay identity must fail closed");
            assert_smart_contract_error(error, "identifier does not match");
            assert_eq!(load_call_record(stx, &call), original_record);
            assert!(stx.world.take_external_events().is_empty());

            let zero_bandwidth = KaigiRelayRegistration {
                relay_id: relay.relay_id.clone(),
                hpke_public_key: relay.hpke_public_key.clone(),
                bandwidth_class: 0,
            };
            stx.world
                .domain_mut(&domain)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    key,
                    Json::try_new(zero_bandwidth).expect("serialize corrupt registration"),
                );
            let error = SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: Some(manifest.clone()),
            }
            .execute(&host, stx)
            .expect_err("zero-bandwidth stored registration must fail closed");
            assert_smart_contract_error(error, "zero bandwidth");
            assert_eq!(load_call_record(stx, &call), original_record);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn transparent_join_updates_roster_summary() {
        let (record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = record.id.domain_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host account");
            Register::account(Account::new(participant.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register participant account");
            stx.world.take_external_events();
            create_call(stx, &record, &host);
            stx.world.take_external_events();
            JoinKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("transparent join");
            let events = stx.world.take_external_events();
            let summary = extract_roster_summary(&events).expect("roster summary event");
            assert_eq!(summary.participant_count, 1);
            assert_eq!(summary.commitment_count, 0);
            assert_eq!(summary.nullifier_count, 0);
        });
    }
    #[test]
    fn rejected_record_write_emits_no_roster_summary() {
        use iroha_data_model::parameter::{CustomParameter, CustomParameterId, Parameter};

        let (record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = call.domain_id.clone();
        with_seeded_kaigi_state_transaction(&domain, &[host.clone(), participant.clone()], |stx| {
            create_call(stx, &record, &host);
            let original = load_call_record(stx, &call);
            let limit_id: CustomParameterId = "max_metadata_value_bytes"
                .parse()
                .expect("metadata limit parameter id");
            stx.world
                .parameters
                .get_mut()
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    limit_id,
                    Json::new(1_u64),
                )));
            stx.world.take_external_events();

            let error = JoinKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("an oversized updated record must be rejected");
            assert_smart_contract_error(error, "Payload too large");
            assert_eq!(load_call_record(stx, &call), original);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn transparent_join_rejects_unregistered_participant_without_mutation() {
        let (record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = call.domain_id.clone();
        with_seeded_kaigi_state_transaction(&domain, std::slice::from_ref(&host), |stx| {
            create_call(stx, &record, &host);
            let original = load_call_record(stx, &call);
            stx.world.take_external_events();

            let error = JoinKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("host must not add an account absent from world state");
            assert!(
                matches!(&error, Error::Find(FindError::Account(account)) if account == &participant),
                "unexpected error: {error:?}"
            );
            assert_eq!(load_call_record(stx, &call), original);
            assert!(stx.world.take_external_events().is_empty());
        });
    }

    #[test]
    fn private_join_updates_commitment_summary_with_real_proof() {
        let (record, host, participant) = new_record(KaigiPrivacyMode::ZkRosterV1);
        let call = record.id.clone();
        with_seeded_kaigi_state_transaction(
            &call.domain_id,
            &[host.clone(), participant.clone()],
            |stx| {
                let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
                template.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
                install_private_create(stx, template);
                let stored = load_call_record(stx, &call);
                let joined = authorization_fixture_v1(
                    stx,
                    &stored,
                    &participant,
                    1,
                    KaigiAuthorizationActionV1::Join,
                    17,
                );
                stx.world.take_external_events();
                JoinKaigi {
                    call_id: call.clone(),
                    participant: participant.clone(),
                    commitment: Some(joined.commitment),
                    nullifier: Some(joined.nullifier),
                    roster_root: Some(joined.root),
                    proof: Some(joined.proof),
                }
                .execute(&participant, stx)
                .unwrap();
                let events = stx.world.take_external_events();
                let summary = extract_roster_summary(&events).unwrap();
                assert_eq!(summary.participant_count, 0);
                assert_eq!(summary.commitment_count, 1);
                assert_eq!(summary.nullifier_count, 2);
            },
        );
    }
    #[test]
    fn leave_kaigi_updates_roster_summary() {
        let (record, host, participant) = new_record(KaigiPrivacyMode::Transparent);
        let call_id = record.id.clone();
        let domain = call_id.domain_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            Register::account(Account::new(participant.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register participant");
            stx.world.take_external_events();
            CreateKaigi {
                call: NewKaigi::with_defaults(call_id.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            JoinKaigi {
                call_id: call_id.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("join kaigi");
            stx.world.take_external_events();
            LeaveKaigi {
                call_id: call_id.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("leave kaigi");
            let events = stx.world.take_external_events();
            let summary = extract_roster_summary(&events).expect("roster summary event");
            assert_eq!(summary.call, call_id);
            assert_eq!(summary.participant_count, 0);
            assert_eq!(summary.commitment_count, 0);
            assert_eq!(summary.nullifier_count, 0);
        });
    }
    #[test]
    fn record_usage_updates_usage_summary() {
        let (record, host, _participant) = new_record(KaigiPrivacyMode::Transparent);
        let domain = record.id.domain_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            stx.world.take_external_events();
            create_call(stx, &record, &host);
            stx.world.take_external_events();
            RecordKaigiUsage {
                call_id: record.id.clone(),
                duration_ms: 90,
                billed_gas: 900,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("record usage");
            let events = stx.world.take_external_events();
            let summary = extract_usage_summary(&events).expect("usage summary event");
            assert_eq!(summary.call, record.id);
            assert_eq!(summary.total_duration_ms, 90);
            assert_eq!(summary.total_billed_gas, 900);
            assert_eq!(summary.segments_recorded, 1);
        });
    }
    #[test]
    fn ended_kaigi_rejects_all_session_mutations() {
        let (domain, host, participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("ended-freeze").unwrap());
        let manifest = sample_manifest();
        let relay_id = manifest.hops[0].relay_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            Register::account(Account::new(participant.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register participant");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            JoinKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("join participant");
            EndKaigi {
                call_id: call.clone(),
                ended_at_ms: Some(0),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("end kaigi");
            let ended_record = load_call_record(stx, &call);
            assert_eq!(ended_record.status, KaigiStatus::Ended);
            stx.world.take_external_events();

            let leave_err = LeaveKaigi {
                call_id: call.clone(),
                participant: participant.clone(),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("ended Kaigi must reject leave");
            assert_kaigi_not_active(leave_err);

            let usage_err = RecordKaigiUsage {
                call_id: call.clone(),
                duration_ms: 1,
                billed_gas: 1,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("ended Kaigi must reject usage");
            assert_kaigi_not_active(usage_err);

            let health_err = ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Unavailable,
                reported_at_ms: 11,
                notes: None,
            }
            .execute(&host, stx)
            .expect_err("ended Kaigi must reject relay health reports");
            assert_kaigi_not_active(health_err);

            let manifest_err = SetKaigiRelayManifest {
                call_id: call.clone(),
                relay_manifest: None,
            }
            .execute(&host, stx)
            .expect_err("ended Kaigi must reject relay manifest updates");
            assert_kaigi_not_active(manifest_err);

            assert_eq!(load_call_record(stx, &call), ended_record);
            let feedback_key = kaigi_relay_feedback_key(&relay_id).expect("feedback key");
            assert!(
                stx.world
                    .domain(&domain)
                    .expect("domain")
                    .metadata()
                    .get(&feedback_key)
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn record_usage_rejects_counter_overflow_without_mutating_state() {
        let (record, host, _participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = call.domain_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            create_call(stx, &record, &host);
            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");

            let mut stored = load_call_record(stx, &call);
            stored.total_duration_ms = u64::MAX;
            store_record(stx, &domain, key.clone(), &stored).expect("seed duration limit");
            stx.world.take_external_events();
            let err = RecordKaigiUsage {
                call_id: call.clone(),
                duration_ms: 1,
                billed_gas: 0,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("duration overflow must reject");
            assert_smart_contract_error(err, "total duration");
            assert_eq!(load_call_record(stx, &call), stored);
            assert!(stx.world.take_external_events().is_empty());

            stored.total_duration_ms = 0;
            stored.total_billed_gas = u64::MAX;
            store_record(stx, &domain, key.clone(), &stored).expect("seed billed gas limit");
            stx.world.take_external_events();
            let err = RecordKaigiUsage {
                call_id: call.clone(),
                duration_ms: 1,
                billed_gas: 1,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("billed gas overflow must reject");
            assert_smart_contract_error(err, "total billed gas");
            assert_eq!(load_call_record(stx, &call), stored);
            assert!(stx.world.take_external_events().is_empty());

            stored.total_billed_gas = 0;
            stored.segments_recorded = u32::MAX;
            store_record(stx, &domain, key, &stored).expect("seed segment count limit");
            stx.world.take_external_events();
            let err = RecordKaigiUsage {
                call_id: call.clone(),
                duration_ms: 1,
                billed_gas: 0,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("segment count overflow must reject");
            assert_smart_contract_error(err, "segment count");
            assert_eq!(load_call_record(stx, &call), stored);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn end_kaigi_rejects_impossible_timestamps_without_mutating_state() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("end-timestamp").expect("call name"),
        );
        with_state_transaction_at(100, |stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            CreateKaigi {
                call: NewKaigi::with_defaults(call.clone(), host.clone()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create kaigi");
            let active = load_call_record(stx, &call);
            let create_events = stx.world.take_external_events();
            let created = extract_status_summary(&create_events).expect("active status event");
            assert_eq!(*created.status(), KaigiStatus::Active);
            assert_eq!(*created.ended_at_ms(), None);
            assert!(create_events.iter().all(|event| !matches!(
                event,
                EventBox::Data(data)
                    if matches!(data.as_ref(), DataEvent::Domain(DomainEvent::MetadataInserted(_)))
            )));

            for (timestamp, message) in [(99, "precede creation"), (101, "current block time")] {
                let error = EndKaigi {
                    call_id: call.clone(),
                    ended_at_ms: Some(timestamp),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&host, stx)
                .expect_err("impossible end timestamp must reject");
                assert_smart_contract_error(error, message);
                assert_eq!(load_call_record(stx, &call), active);
                assert!(stx.world.take_external_events().is_empty());
            }

            EndKaigi {
                call_id: call.clone(),
                ended_at_ms: Some(100),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("current block time is a valid end timestamp");
            assert_eq!(load_call_record(stx, &call).ended_at_ms, Some(100));
            let end_events = stx.world.take_external_events();
            assert_eq!(
                end_events.len(),
                1,
                "ending exposes only a compact status event"
            );
            let ended = extract_status_summary(&end_events).expect("ended status event");
            assert_eq!(*ended.status(), KaigiStatus::Ended);
            assert_eq!(*ended.ended_at_ms(), Some(100));
        });
    }
    #[test]
    fn stored_record_identifier_must_match_requested_call() {
        let (record, host, _participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = call.domain_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            create_call(stx, &record, &host);

            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            let mut mismatched = load_call_record(stx, &call);
            mismatched.id = KaigiId::new(
                domain.clone(),
                Name::from_str("different-call").expect("call name"),
            );
            stx.world
                .domain_mut(&domain)
                .expect("domain")
                .metadata_mut()
                .insert(
                    key,
                    Json::try_new(mismatched.clone()).expect("serialize mismatched record"),
                );
            stx.world.take_external_events();

            let err = RecordKaigiUsage {
                call_id: call.clone(),
                duration_ms: 1,
                billed_gas: 1,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("mismatched stored identifier must reject");
            assert_invariant_error(err, "identifier does not match metadata key");
            assert_eq!(load_call_record(stx, &call), mismatched);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn stored_record_relay_manifest_must_satisfy_v1_constraints() {
        let (record, host, _participant) = new_record(KaigiPrivacyMode::Transparent);
        let call = record.id.clone();
        let domain = call.domain_id.clone();
        with_state_transaction(|stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            create_call(stx, &record, &host);

            let key = kaigi_metadata_key(&call.call_name).expect("metadata key");
            let mut persisted = load_call_record(stx, &call);
            let mut too_many = sample_manifest();
            while too_many.hops.len() <= KAIGI_RELAY_MANIFEST_MAX_HOPS_V1 {
                too_many.hops.push(too_many.hops[0].clone());
            }
            persisted.relay_manifest = Some(too_many);
            stx.world
                .domain_mut(&domain)
                .expect("domain")
                .metadata_mut()
                .insert(
                    key.clone(),
                    Json::try_new(persisted.clone()).expect("serialize oversized manifest"),
                );
            stx.world.take_external_events();

            let error = RecordKaigiUsage {
                call_id: call.clone(),
                duration_ms: 1,
                billed_gas: 1,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("a persisted overlong relay manifest must fail closed");
            assert_invariant_error(error, "relay manifest violates V1 constraints");
            assert_eq!(load_call_record(stx, &call), persisted);
            assert!(stx.world.take_external_events().is_empty());

            let mut oversized_key = sample_manifest();
            oversized_key.hops[0].hpke_public_key =
                vec![0xA5; KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1 + 1];
            persisted.relay_manifest = Some(oversized_key);
            stx.world
                .domain_mut(&domain)
                .expect("domain")
                .metadata_mut()
                .insert(
                    key,
                    Json::try_new(persisted.clone()).expect("serialize oversized relay key"),
                );

            let error = RecordKaigiUsage {
                call_id: call.clone(),
                duration_ms: 1,
                billed_gas: 1,
                usage_commitment: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect_err("a persisted oversized relay key must fail closed");
            assert_invariant_error(error, "relay manifest violates V1 constraints");
            assert_eq!(load_call_record(stx, &call), persisted);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn relay_health_report_rejects_observation_before_call_creation() {
        let (domain, host, _) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("health-precreation").expect("call name"),
        );
        let manifest = sample_manifest();
        let relay_id = manifest.hops[0].relay_id.clone();
        with_state_transaction_at(20, |stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            CreateKaigi {
                call: template,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            }
            .execute(&host, stx)
            .expect("create call at block time 20");
            stx.world.take_external_events();
            let record_before = load_call_record(stx, &call);
            assert_eq!(record_before.created_at_ms, 20);
            let internal_events_before = stx.world.internal_event_buf.len();

            let error = ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 19,
                notes: None,
            }
            .execute(&host, stx)
            .expect_err("observation before creation must not be admitted");
            assert_smart_contract_error(error, "precedes Kaigi creation");
            assert_eq!(load_call_record(stx, &call), record_before);
            assert!(
                load_relay_feedback(stx, &relay_id)
                    .expect("load feedback")
                    .is_none()
            );
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(stx.world.internal_event_buf.len(), internal_events_before);

            ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 20,
                notes: None,
            }
            .execute(&host, stx)
            .expect("observation at creation time is valid");
            assert_eq!(
                load_relay_feedback(stx, &relay_id)
                    .expect("load feedback")
                    .expect("stored feedback")
                    .reported_at_ms,
                20
            );
        });
    }
    #[test]
    fn relay_health_reports_are_monotonic_and_idempotent() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("health-ordering").expect("call name"),
        );
        let manifest = sample_manifest();
        let relay_id = manifest.hops[0].relay_id.clone();
        with_state_transaction_at(20, |stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            store_kaigi_record_for_testing(stx, &KaigiRecord::from_new(&template, 0))
                .expect("retain a call created before this observation block");
            stx.world.take_external_events();

            let initial_record = load_call_record(stx, &call);
            let feedback_key =
                kaigi_relay_feedback_key(&relay_id).expect("relay feedback metadata key");
            let corrupt_feedback = KaigiRelayFeedback {
                relay_id: manifest.hops[1].relay_id.clone(),
                call: call.clone(),
                reported_by: host.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 1,
                notes: None,
            };
            stx.world
                .domain_mut(&domain)
                .expect("relay domain")
                .metadata_mut()
                .insert(
                    feedback_key.clone(),
                    Json::try_new(corrupt_feedback).expect("serialize corrupt feedback"),
                );
            let corrupt_error = ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 10,
                notes: None,
            }
            .execute(&host, stx)
            .expect_err("mismatched stored relay feedback must fail closed");
            assert_invariant_error(corrupt_error, "identifier does not match");
            assert_eq!(load_call_record(stx, &call), initial_record);
            assert!(stx.world.take_external_events().is_empty());
            stx.world
                .domain_mut(&domain)
                .expect("relay domain")
                .metadata_mut()
                .remove(&feedback_key)
                .expect("remove corrupt feedback");

            let future_error = ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Unavailable,
                reported_at_ms: u64::MAX,
                notes: Some("poison".to_owned()),
            }
            .execute(&host, stx)
            .expect_err("a future report must not poison feedback ordering");
            assert_smart_contract_error(future_error, "current block time");
            assert!(
                load_relay_feedback(stx, &relay_id)
                    .expect("load feedback")
                    .is_none()
            );
            assert_eq!(load_call_record(stx, &call), initial_record);
            assert!(stx.world.take_external_events().is_empty());

            ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 10,
                notes: Some("baseline".to_owned()),
            }
            .execute(&host, stx)
            .expect("store baseline feedback");
            let baseline_feedback = load_relay_feedback(stx, &relay_id)
                .expect("load feedback")
                .expect("baseline feedback");
            let baseline_record = load_call_record(stx, &call);
            assert!(!stx.world.take_external_events().is_empty());

            ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 10,
                notes: Some("baseline".to_owned()),
            }
            .execute(&host, stx)
            .expect("an exact duplicate is an idempotent no-op");
            assert_eq!(
                load_relay_feedback(stx, &relay_id)
                    .expect("load feedback")
                    .expect("stored feedback"),
                baseline_feedback
            );
            assert_eq!(load_call_record(stx, &call), baseline_record);
            assert!(stx.world.take_external_events().is_empty());

            let stale_error = ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Unavailable,
                reported_at_ms: 9,
                notes: Some("stale".to_owned()),
            }
            .execute(&host, stx)
            .expect_err("an older report must not replace current feedback");
            assert_smart_contract_error(stale_error, "older than the latest");
            assert_eq!(
                load_relay_feedback(stx, &relay_id)
                    .expect("load feedback")
                    .expect("stored feedback"),
                baseline_feedback
            );
            assert_eq!(load_call_record(stx, &call), baseline_record);
            assert!(stx.world.take_external_events().is_empty());

            let conflict_error = ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Degraded,
                reported_at_ms: 10,
                notes: Some("conflict".to_owned()),
            }
            .execute(&host, stx)
            .expect_err("equal-timestamp conflicting feedback must reject");
            assert_smart_contract_error(conflict_error, "same timestamp");
            assert_eq!(
                load_relay_feedback(stx, &relay_id)
                    .expect("load feedback")
                    .expect("stored feedback"),
                baseline_feedback
            );
            assert_eq!(load_call_record(stx, &call), baseline_record);
            assert!(stx.world.take_external_events().is_empty());

            ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Unavailable,
                reported_at_ms: 11,
                notes: Some("newer".to_owned()),
            }
            .execute(&host, stx)
            .expect("newer feedback replaces the current value");
            let latest = load_relay_feedback(stx, &relay_id)
                .expect("load feedback")
                .expect("latest feedback");
            assert_eq!(latest.status, KaigiRelayHealthStatus::Unavailable);
            assert_eq!(latest.reported_at_ms, 11);
            assert_eq!(load_call_record(stx, &call), baseline_record);
            assert!(!stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn equal_timestamp_relay_health_reports_reject_across_calls() {
        let (domain, first_host, second_host) = sample_ids();
        let first_call = KaigiId::new(
            domain.clone(),
            Name::from_str("health-call-a").expect("call name"),
        );
        let second_call = KaigiId::new(
            domain.clone(),
            Name::from_str("health-call-b").expect("call name"),
        );
        let manifest = sample_manifest();
        let relay_id = manifest.hops[0].relay_id.clone();
        with_state_transaction_at(20, |stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            for host in [first_host.clone(), second_host.clone()] {
                Register::account(Account::new(host))
                    .execute(&ALICE_ID, stx)
                    .expect("register host");
            }
            register_manifest_relays(stx, &domain, &manifest);
            for (call, host) in [
                (first_call.clone(), first_host.clone()),
                (second_call.clone(), second_host.clone()),
            ] {
                let mut template = NewKaigi::with_defaults(call, host.clone());
                template.relay_manifest = Some(manifest.clone());
                store_kaigi_record_for_testing(stx, &KaigiRecord::from_new(&template, 0))
                    .expect("retain a call created before this observation block");
            }
            stx.world.take_external_events();

            ReportKaigiRelayHealth {
                call_id: first_call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 10,
                notes: Some("first call".to_owned()),
            }
            .execute(&first_host, stx)
            .expect("store first call feedback");
            stx.world.take_external_events();

            let conflict = ReportKaigiRelayHealth {
                call_id: first_call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Degraded,
                reported_at_ms: 10,
                notes: Some("same call conflict".to_owned()),
            }
            .execute(&first_host, stx)
            .expect_err("same-call equal-timestamp conflict must reject");
            assert_smart_contract_error(conflict, "same timestamp");
            assert!(stx.world.take_external_events().is_empty());

            let cross_call_conflict = ReportKaigiRelayHealth {
                call_id: second_call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Degraded,
                reported_at_ms: 10,
                notes: Some("second call".to_owned()),
            }
            .execute(&second_host, stx)
            .expect_err("equal-timestamp feedback must have deterministic singleton ordering");
            assert_smart_contract_error(cross_call_conflict, "same timestamp");
            let latest = load_relay_feedback(stx, &relay_id)
                .expect("load feedback")
                .expect("stored feedback");
            assert_eq!(latest.call, first_call);
            assert_eq!(latest.status, KaigiRelayHealthStatus::Healthy);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn relay_health_note_limit_counts_unicode_characters() {
        let (domain, host, _participant) = sample_ids();
        let call = KaigiId::new(domain.clone(), Name::from_str("unicode-health").unwrap());
        let manifest = sample_manifest();
        let relay_id = manifest.hops[0].relay_id.clone();
        with_state_transaction_at(20, |stx| {
            Register::domain(Domain::new(domain.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            Register::account(Account::new(host.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register host");
            register_manifest_relays(stx, &domain, &manifest);
            let mut template = NewKaigi::with_defaults(call.clone(), host.clone());
            template.relay_manifest = Some(manifest.clone());
            store_kaigi_record_for_testing(stx, &KaigiRecord::from_new(&template, 0))
                .expect("retain a call created before this observation block");
            stx.world.take_external_events();

            let accepted_notes = "界".repeat(512);
            ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Healthy,
                reported_at_ms: 1,
                notes: Some(accepted_notes.clone()),
            }
            .execute(&host, stx)
            .expect("512 multibyte characters must be accepted");
            let feedback_key = kaigi_relay_feedback_key(&relay_id).expect("feedback key");
            let stored: KaigiRelayFeedback = stx
                .world
                .domain(&domain)
                .expect("domain")
                .metadata()
                .get(&feedback_key)
                .expect("stored feedback")
                .clone()
                .try_into_any_norito()
                .expect("decode feedback");
            assert_eq!(stored.notes.as_deref(), Some(accepted_notes.as_str()));
            stx.world.take_external_events();

            let err = ReportKaigiRelayHealth {
                call_id: call.clone(),
                relay_id: relay_id.clone(),
                status: KaigiRelayHealthStatus::Degraded,
                reported_at_ms: 2,
                notes: Some("界".repeat(513)),
            }
            .execute(&host, stx)
            .expect_err("513 characters must be rejected");
            assert_smart_contract_error(err, "512 characters");
            let unchanged: KaigiRelayFeedback = stx
                .world
                .domain(&domain)
                .expect("domain")
                .metadata()
                .get(&feedback_key)
                .expect("stored feedback")
                .clone()
                .try_into_any_norito()
                .expect("decode feedback");
            assert_eq!(unchanged, stored);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
    #[test]
    fn active_rekey_successor_can_end_predecessor_hosted_kaigi() {
        let (domain, retired_host, unrelated) = sample_ids();
        let (active_host, _) = gen_account_in("nexus");
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("rekey-host-end").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(
            &domain,
            &[active_host.clone(), unrelated.clone()],
            |stx| {
                seed_active_account_id_rekey_lineage(
                    stx,
                    "kaigi-host-lineage",
                    &retired_host,
                    &active_host,
                );
                let template = NewKaigi::with_defaults(call.clone(), retired_host.clone());
                let record = KaigiRecord::from_new(&template, 0);
                store_record(
                    stx,
                    &domain,
                    kaigi_metadata_key(&call.call_name).expect("metadata key"),
                    &record,
                )
                .expect("seed predecessor-hosted call");
                stx.world.take_external_events();

                let error = EndKaigi {
                    call_id: call.clone(),
                    ended_at_ms: Some(0),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&unrelated, stx)
                .expect_err("unrelated account must not inherit host authority");
                assert_smart_contract_error(error, "only the host");
                assert_eq!(load_call_record(stx, &call), record);
                assert!(stx.world.take_external_events().is_empty());

                EndKaigi {
                    call_id: call.clone(),
                    ended_at_ms: Some(0),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&active_host, stx)
                .expect("active rekey successor may end predecessor-hosted call");
                let ended = load_call_record(stx, &call);
                assert_eq!(ended.host, retired_host, "audit identity stays historical");
                assert_eq!(ended.status, KaigiStatus::Ended);
                assert_eq!(ended.ended_at_ms, Some(0));
            },
        );
    }
    #[test]
    fn active_rekey_successor_can_leave_predecessor_roster_entry() {
        let (domain, host, retired_participant) = sample_ids();
        let (active_participant, _) = gen_account_in("nexus");
        let (unrelated, _) = gen_account_in("nexus");
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("rekey-participant-leave").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(
            &domain,
            &[host.clone(), active_participant.clone(), unrelated.clone()],
            |stx| {
                seed_active_account_id_rekey_lineage(
                    stx,
                    "kaigi-participant-lineage",
                    &retired_participant,
                    &active_participant,
                );
                let template = NewKaigi::with_defaults(call.clone(), host.clone());
                let mut record = KaigiRecord::from_new(&template, 0);
                record.push_participant(retired_participant.clone());
                record
                    .participant_metadata
                    .insert(retired_participant.clone(), Metadata::default());
                store_record(
                    stx,
                    &domain,
                    kaigi_metadata_key(&call.call_name).expect("metadata key"),
                    &record,
                )
                .expect("seed predecessor roster entry");
                stx.world.take_external_events();

                let error = LeaveKaigi {
                    call_id: call.clone(),
                    participant: active_participant.clone(),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&unrelated, stx)
                .expect_err("unrelated account must not inherit participant authority");
                assert_smart_contract_error(error, "only the host or participant");
                assert_eq!(load_call_record(stx, &call), record);
                assert!(stx.world.take_external_events().is_empty());

                LeaveKaigi {
                    call_id: call.clone(),
                    participant: active_participant.clone(),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&active_participant, stx)
                .expect("active successor may remove predecessor roster entry");
                let updated = load_call_record(stx, &call);
                assert!(updated.participants.is_empty());
                assert!(updated.participant_metadata.is_empty());
                assert_eq!(updated.host, host);
            },
        );
    }
    #[test]
    fn private_original_owner_and_departed_dependency_survive_authenticated_rekey() {
        let (mut record, host, original) = new_record(KaigiPrivacyMode::ZkRosterV1);
        let (successor, _) = gen_account_in("nexus");
        let domain = record.id.domain_id.clone();
        let commitment = sample_commitment();
        record
            .private_participation
            .commit_join(&original, 1, commitment.commitment)
            .unwrap();
        record.push_commitment(commitment);
        with_seeded_kaigi_state_transaction(&domain, &[host.clone(), successor.clone()], |stx| {
            seed_active_account_id_rekey_lineage(
                stx,
                "private-original-owner",
                &original,
                &successor,
            );
            validate_private_participation_lineages(&stx.world, &record).unwrap();
            let graph = persisted_kaigi_rekey_graph(&stx.world, [successor.clone()]).unwrap();
            assert!(
                record_has_participant_in_active_lineage(stx, &record, &successor, &graph).unwrap()
            );
            assert_eq!(
                original_participant_v1(
                    stx,
                    &record.private_participation,
                    &host,
                    &successor,
                    &successor,
                    KaigiAuthorizationActionV1::Leave
                )
                .unwrap(),
                original
            );
            assert!(
                original_participant_v1(
                    stx,
                    &record.private_participation,
                    &host,
                    &successor,
                    &original,
                    KaigiAuthorizationActionV1::Leave
                )
                .is_err()
            );
            record
                .private_participation
                .commit_leave(&original, 1, commitment.commitment)
                .unwrap();
            assert!(record.remove_commitment(&commitment));
            assert!(active_call_dependency_accounts(&record).contains(&original));
            assert!(
                !record_has_participant_in_active_lineage(stx, &record, &successor, &graph)
                    .unwrap()
            );
            assert_eq!(
                original_participant_v1(
                    stx,
                    &record.private_participation,
                    &host,
                    &successor,
                    &successor,
                    KaigiAuthorizationActionV1::Join
                )
                .unwrap(),
                original
            );
            assert_eq!(
                record
                    .private_participation
                    .prepare_join(&original)
                    .unwrap(),
                2
            );
            let mut duplicate = record.clone();
            let other = KaigiParticipantCommitment {
                commitment: test_scalar(31),
            };
            duplicate
                .private_participation
                .commit_join(&successor, 1, other.commitment)
                .unwrap();
            duplicate.push_commitment(other);
            assert!(validate_private_participation_lineages(&stx.world, &duplicate).is_err());
            assert!(
                record_has_participant_in_active_lineage(stx, &duplicate, &successor, &graph)
                    .is_err()
            );
            record.status = KaigiStatus::Ended;
            record.ended_at_ms = Some(record.created_at_ms);
            assert!(active_call_dependency_accounts(&record).is_empty());
        });
    }
    #[test]
    fn participant_lookup_rejects_multiple_ids_from_one_rekey_component_atomically() {
        let (domain, host, retired_participant) = sample_ids();
        let (active_participant, _) = gen_account_in("nexus");
        let call = KaigiId::new(
            domain.clone(),
            Name::from_str("duplicate-lineage-participants").expect("call name"),
        );
        with_seeded_kaigi_state_transaction(
            &domain,
            &[host.clone(), active_participant.clone()],
            |stx| {
                seed_active_account_id_rekey_lineage(
                    stx,
                    "duplicate-kaigi-participant-lineage",
                    &retired_participant,
                    &active_participant,
                );
                let mut record =
                    KaigiRecord::from_new(&NewKaigi::with_defaults(call.clone(), host.clone()), 0);
                record.participants = vec![retired_participant.clone(), active_participant.clone()];
                record.participants.sort_unstable();
                store_record(
                    stx,
                    &domain,
                    kaigi_metadata_key(&call.call_name).expect("metadata key"),
                    &record,
                )
                .expect("seed distinct identities from one persisted lineage");
                stx.world.take_external_events();

                let error = LeaveKaigi {
                    call_id: call.clone(),
                    participant: active_participant.clone(),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .execute(&host, stx)
                .expect_err("one active lineage must not occupy multiple roster slots");
                assert_invariant_error(error, "multiple Kaigi participants resolve");
                assert_eq!(load_call_record(stx, &call), record);
                assert!(stx.world.take_external_events().is_empty());
            },
        );
    }
    pub(super) fn register_manifest_relays(
        stx: &mut StateTransaction<'_, '_>,
        domain_id: &DomainId,
        manifest: &KaigiRelayManifest,
    ) {
        for hop in &manifest.hops {
            Register::account(Account::new(hop.relay_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register manifest relay account");
            add_relay_to_allowlist(stx, domain_id, &hop.relay_id);
        }
        for hop in &manifest.hops {
            RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: hop.relay_id.clone(),
                    hpke_public_key: hop.hpke_public_key.clone(),
                    bandwidth_class: 1,
                },
            }
            .execute(&hop.relay_id, stx)
            .expect("register manifest relay");
        }
        stx.world.take_external_events();
    }
    fn add_relay_to_allowlist(
        stx: &mut StateTransaction<'_, '_>,
        domain_id: &DomainId,
        relay_id: &AccountId,
    ) {
        seed_relay_primary_alias_for_testing(stx, domain_id, relay_id);
        let key = kaigi_relay_allowlist_key().expect("allowlist key");
        let domain = stx
            .world
            .domain_mut(domain_id)
            .expect("relay domain exists");
        let mut allowlist: KaigiRelayAllowlist = domain
            .metadata_mut()
            .remove(&key)
            .map(|value| {
                value
                    .try_into_any_norito()
                    .expect("deserialize stored allowlist")
            })
            .unwrap_or_default();
        allowlist.allowed_relays.insert(relay_id.clone());
        let value = Json::try_new(allowlist).expect("serialize allowlist");
        domain.metadata_mut().insert(key, value);
    }
    fn seed_relay_primary_alias_for_testing(
        stx: &mut StateTransaction<'_, '_>,
        domain_id: &DomainId,
        relay_id: &AccountId,
    ) {
        use iroha_data_model::{
            account::{
                AccountAddress,
                rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
            },
            sns::{NameControllerV1, NameRecordV1},
        };
        if stx
            .world
            .account(relay_id)
            .expect("relay account exists")
            .label()
            .is_some()
        {
            return;
        }
        let metadata_key = kaigi_relay_metadata_key(relay_id).expect("relay metadata key");
        let digest = metadata_key
            .as_ref()
            .strip_prefix("kaigi_relay__")
            .expect("relay metadata key prefix");
        let label = Name::from_str(&format!("relay{}", &digest[..16])).expect("relay alias label");
        let dataspace = stx
            .world
            .dataspace_catalog()
            .by_alias(domain_id.dataspace().as_ref())
            .expect("relay domain dataspace exists")
            .id;
        let alias = AccountAlias::new(
            label,
            Some(AccountAliasDomain::new(domain_id.name().clone())),
            dataspace,
        );
        let selector =
            crate::sns::selector_for_account_alias(&alias, stx.world.dataspace_catalog())
                .expect("relay alias selector");
        let address = AccountAddress::from_account_id(relay_id).expect("relay account address");
        let lease = NameRecordV1::new(
            selector.clone(),
            relay_id.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        stx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&lease),
        );
        stx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(alias.clone(), relay_id.clone()));
        stx.world
            .account_mut(relay_id)
            .expect("relay account exists")
            .set_label(Some(alias.clone()));
        stx.world
            .insert_account_alias_binding(alias, relay_id.clone());
    }
    fn expire_relay_primary_alias_for_testing(
        stx: &mut StateTransaction<'_, '_>,
        relay_id: &AccountId,
    ) {
        use iroha_data_model::{
            account::AccountAddress,
            sns::{NameControllerV1, NameRecordV1},
        };
        let alias = stx
            .world
            .account(relay_id)
            .expect("relay account exists")
            .label()
            .cloned()
            .expect("relay primary alias exists");
        let selector =
            crate::sns::selector_for_account_alias(&alias, stx.world.dataspace_catalog())
                .expect("relay alias selector");
        let address = AccountAddress::from_account_id(relay_id).expect("relay account address");
        let expired = NameRecordV1::new(
            selector.clone(),
            relay_id.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            0,
            0,
            0,
            Metadata::default(),
        );
        stx.world.smart_contract_state.insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&expired),
        );
    }
    fn seed_kaigi_account_dependency_for_testing(
        stx: &mut StateTransaction<'_, '_>,
        account: &AccountId,
        dependency: KaigiAccountDependencyLocator,
    ) {
        apply_kaigi_account_dependency_replacement(
            stx,
            &dependency,
            &BTreeSet::new(),
            &BTreeSet::from([account.clone()]),
        );
    }
    fn remove_kaigi_account_dependency_for_testing(
        stx: &mut StateTransaction<'_, '_>,
        account: &AccountId,
        dependency: &KaigiAccountDependencyLocator,
    ) {
        apply_kaigi_account_dependency_replacement(
            stx,
            dependency,
            &BTreeSet::from([account.clone()]),
            &BTreeSet::new(),
        );
    }
    pub(super) fn load_call_record(
        stx: &StateTransaction<'_, '_>,
        call_id: &KaigiId,
    ) -> KaigiRecord {
        let key = kaigi_metadata_key(&call_id.call_name).expect("metadata key");
        stx.world
            .domain(&call_id.domain_id)
            .expect("domain")
            .metadata()
            .get(&key)
            .expect("record metadata")
            .clone()
            .try_into_any_norito()
            .expect("deserialize record")
    }
    pub(super) fn load_relay_registration(
        stx: &StateTransaction<'_, '_>,
        domain_id: &DomainId,
        relay_id: &AccountId,
    ) -> Option<KaigiRelayRegistration> {
        let key = kaigi_relay_metadata_key(relay_id).expect("relay registration key");
        stx.world
            .domain(domain_id)
            .expect("relay domain")
            .metadata()
            .get(&key)
            .cloned()
            .map(|value| {
                value
                    .try_into_any_norito()
                    .expect("decode relay registration")
            })
    }
    fn assert_kaigi_not_active(error: Error) {
        assert_invariant_error(error, "Kaigi is not active");
    }
    pub(super) fn assert_invariant_error(
        error: impl Into<ExecutionAttemptError<Error>>,
        expected: &str,
    ) {
        match crate::execution_attempt::expect_completed_rejection(error.into()) {
            Error::InvariantViolation(message) => {
                assert!(message.contains(expected), "unexpected error: {message}");
            }
            other => panic!("unexpected error variant {other:?}"),
        }
    }
    pub(super) fn assert_smart_contract_error(error: Error, expected: &str) {
        match error {
            Error::InvalidParameter(InvalidParameterError::SmartContract(message)) => {
                assert!(message.contains(expected), "unexpected error: {message}");
            }
            other => panic!("unexpected error variant {other:?}"),
        }
    }
    fn create_call(stx: &mut StateTransaction<'_, '_>, record: &KaigiRecord, host: &AccountId) {
        CreateKaigi {
            call: NewKaigi::with_defaults(record.id.clone(), host.clone()),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .execute(host, stx)
        .expect("create kaigi");
    }
    pub(super) fn sample_manifest() -> KaigiRelayManifest {
        let (relay_a, _) = gen_account_in("relay");
        let (relay_b, _) = gen_account_in("relay");
        let (relay_c, _) = gen_account_in("relay");
        KaigiRelayManifest {
            hops: vec![
                KaigiRelayHop {
                    relay_id: relay_a,
                    hpke_public_key: vec![1, 2, 3],
                    weight: 1,
                },
                KaigiRelayHop {
                    relay_id: relay_b,
                    hpke_public_key: vec![4, 5, 6],
                    weight: 1,
                },
                KaigiRelayHop {
                    relay_id: relay_c,
                    hpke_public_key: vec![7, 8, 9],
                    weight: 1,
                },
            ],
            expiry_ms: 42,
        }
    }
    fn extract_roster_summary(events: &[EventBox]) -> Option<KaigiRosterSummary> {
        events.iter().find_map(|event| {
            if let EventBox::Data(ev) = event {
                if let DataEvent::Domain(DomainEvent::KaigiRosterSummary(summary)) = ev.as_ref() {
                    return Some(summary.clone());
                }
            }
            None
        })
    }
    fn extract_registration_summary(events: &[EventBox]) -> Option<KaigiRelayRegistrationSummary> {
        events.iter().find_map(|event| {
            if let EventBox::Data(ev) = event {
                if let DataEvent::Domain(DomainEvent::KaigiRelayRegistered(summary)) = ev.as_ref() {
                    return Some(summary.clone());
                }
            }
            None
        })
    }
    fn extract_unregistration_summary(
        events: &[EventBox],
    ) -> Option<KaigiRelayUnregistrationSummary> {
        events.iter().find_map(|event| {
            if let EventBox::Data(ev) = event {
                if let DataEvent::Domain(DomainEvent::KaigiRelayUnregistered(summary)) = ev.as_ref()
                {
                    return Some(summary.clone());
                }
            }
            None
        })
    }
    fn extract_status_summary(events: &[EventBox]) -> Option<KaigiStatusSummary> {
        events.iter().find_map(|event| {
            if let EventBox::Data(ev) = event {
                if let DataEvent::Domain(DomainEvent::KaigiStatusChanged(summary)) = ev.as_ref() {
                    return Some(summary.clone());
                }
            }
            None
        })
    }
    fn extract_manifest_summary(events: &[EventBox]) -> Option<KaigiRelayManifestSummary> {
        events.iter().find_map(|event| {
            if let EventBox::Data(ev) = event {
                if let DataEvent::Domain(DomainEvent::KaigiRelayManifestUpdated(summary)) =
                    ev.as_ref()
                {
                    return Some(summary.clone());
                }
            }
            None
        })
    }
    fn extract_usage_summary(events: &[EventBox]) -> Option<KaigiUsageSummary> {
        events.iter().find_map(|event| {
            if let EventBox::Data(ev) = event {
                if let DataEvent::Domain(DomainEvent::KaigiUsageSummary(summary)) = ev.as_ref() {
                    return Some(summary.clone());
                }
            }
            None
        })
    }
}
