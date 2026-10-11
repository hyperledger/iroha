//! Portable immutable custody of one closed native pin/control request and exact signature.
//!
//! The shared wallet Journal owns private paths, atomic publication and exposure markers. This
//! layer owns purpose/byte equality. It supplies neither current-state evidence nor a Queue permit.

use eyre::{Result, ensure};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionPayload,
    },
};
use iroha_operation_journal::{Journal, NativeRecord};
use iroha_version::codec::DecodeVersioned as _;
use norito::json::{JsonDeserialize, JsonSerialize};
use sha2::{Digest as _, Sha256};
use std::{cell::Cell, path::Path, time::Instant};

use super::authorization::NativePinAuthorizationV1;

pub(in crate::musubi_publication_service) const MAX_FRAME_BYTES: usize = 128 * 1024;
const LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    MAX_FRAME_BYTES,
    MAX_FRAME_BYTES,
    4 * MAX_FRAME_BYTES,
    8 * 1024 * 1024,
    32,
);

/// Fixed slot purposes selected only by the native coordinator, never arbitrary request strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(in crate::musubi_publication_service) enum SlotKind {
    Pin,
    Initialize,
    Advance,
    Check(u16),
}

#[derive(Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(in crate::musubi_publication_service) struct SlotRequest {
    pub(in crate::musubi_publication_service) network: NetworkId,
    pub(in crate::musubi_publication_service) authority: AccountId,
    pub(in crate::musubi_publication_service) session: [u8; 32],
    pub(in crate::musubi_publication_service) operation: [u8; 32],
    pub(in crate::musubi_publication_service) kind: SlotKind,
    /// Original manifest-selection time; required null for control slots. A pin retry never
    /// recalculates its retention from a later quote or signature time.
    #[norito(required)]
    pub(in crate::musubi_publication_service) pin_selected_at_unix_ms: Option<u64>,
    /// Canonical exact single InstructionBox frame selected by the purpose owner.
    pub(in crate::musubi_publication_service) instruction: String,
    pub(in crate::musubi_publication_service) authorization: NativePinAuthorizationV1,
}
impl SlotRequest {
    pub(in crate::musubi_publication_service) fn validate(&self) -> Result<()> {
        self.authorization.validate()?;
        ensure!(
            self.network.as_bytes()[31] & 1 == 1
                && self.session != [0; 32]
                && self.operation != [0; 32],
            "native pin slot identity is invalid"
        );
        ensure!(
            self.authority.try_signatory().is_some(),
            "native pin slot requires direct authority"
        );
        ensure!(
            matches!(self.kind, SlotKind::Pin) == self.pin_selected_at_unix_ms.is_some()
                && self.pin_selected_at_unix_ms.is_none_or(
                    |selected| selected > 0 && selected < self.authorization.deadline_unix_ms
                ),
            "native pin manifest selection time differs from its purpose or original authorization"
        );
        let instruction: iroha_data_model::isi::InstructionBox = decode_frame(&self.instruction)?;
        use iroha_data_model::isi::{
            musubi::{AdvanceMusubiPinOutboxV1, CheckMusubiPinOutboxV1},
            sorafs::RegisterPinManifest,
        };
        match self.kind {
            SlotKind::Pin => {
                let pin = instruction
                    .as_any()
                    .downcast_ref::<RegisterPinManifest>()
                    .ok_or_else(|| eyre::eyre!("native pin slot instruction differs"))?;
                ensure!(
                    pin.alias.is_none() && pin.successor_of.is_none(),
                    "native pin slot is not an initial pin"
                );
                // Full original archive, manifest policy and principal checks belong to the native
                // pin signer. Custody refuses even an incorrectly decoded manifest here.
                sorafs_manifest::decode_manifest_v1_canonical(&pin.manifest_payload)?;
            }
            SlotKind::Initialize | SlotKind::Advance => {
                let value = instruction
                    .as_any()
                    .downcast_ref::<AdvanceMusubiPinOutboxV1>()
                    .ok_or_else(|| eyre::eyre!("native outbox slot instruction differs"))?;
                value.validate()?;
                ensure!(
                    value.network_id == self.network
                        && value.pin_authority == self.authority
                        && value.session_id == self.session
                        && (value.expected_revision == 0)
                            == matches!(self.kind, SlotKind::Initialize),
                    "native outbox slot original binding differs"
                );
            }
            SlotKind::Check(round) => {
                ensure!(
                    round > 0 && round <= self.authorization.max_check_rounds,
                    "native Check slot is outside the original round allowance"
                );
                let value = instruction
                    .as_any()
                    .downcast_ref::<CheckMusubiPinOutboxV1>()
                    .ok_or_else(|| eyre::eyre!("native Check slot instruction differs"))?;
                ensure!(
                    norito::canonical_frame_len(value)?
                        <= iroha_data_model::isi::musubi::MUSUBI_PIN_OUTBOX_CHECK_MAX_BYTES_V1,
                    "native Check exceeds its canonical frame bound"
                );
                value.validate_fields()?;
                ensure!(
                    value.network_id == self.network
                        && value.pin_authority == self.authority
                        && value.session_id == self.session,
                    "native Check slot original binding differs"
                );
            }
        }
        Ok(())
    }
    pub(in crate::musubi_publication_service) fn validate_pin_policy(
        &self,
        storage_class: iroha_data_model::sorafs::pin_registry::StorageClass,
        retention_horizon_secs: u64,
    ) -> Result<()> {
        self.validate()?;
        if self.kind != SlotKind::Pin {
            return Ok(());
        }
        let selected = self
            .pin_selected_at_unix_ms
            .ok_or_else(|| eyre::eyre!("original pin selection missing"))?;
        let retention = selected
            .div_ceil(1_000)
            .checked_add(iroha_data_model::transaction::DEFAULT_TRANSACTION_TIME_TO_LIVE.as_secs())
            .and_then(|epoch| epoch.checked_add(retention_horizon_secs))
            .ok_or_else(|| eyre::eyre!("original pin retention overflow"))?;
        let instruction: iroha_data_model::isi::InstructionBox = decode_frame(&self.instruction)?;
        let pin = instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::sorafs::RegisterPinManifest>()
            .ok_or_else(|| eyre::eyre!("original pin instruction differs"))?;
        let manifest = sorafs_manifest::decode_manifest_v1_canonical(&pin.manifest_payload)?;
        let class = match storage_class {
            iroha_data_model::sorafs::pin_registry::StorageClass::Hot => {
                sorafs_manifest::StorageClass::Hot
            }
            iroha_data_model::sorafs::pin_registry::StorageClass::Warm => {
                sorafs_manifest::StorageClass::Warm
            }
            iroha_data_model::sorafs::pin_registry::StorageClass::Cold => {
                sorafs_manifest::StorageClass::Cold
            }
        };
        ensure!(
            manifest.pin_policy.storage_class == class
                && manifest.pin_policy.retention_epoch == retention
                && manifest.pin_policy.min_replicas >= 3
                && manifest.alias_claims.is_empty()
                && manifest.metadata.is_empty()
                && manifest.governance.council_signatures.is_empty(),
            "retained pin changed its original paid storage policy"
        );
        Ok(())
    }
    pub(in crate::musubi_publication_service) fn hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(norito::json::to_json_bounded_boxed(self, 512 * 1024)?).into())
    }
    fn validate_payload(&self, payload: &TransactionPayload) -> Result<()> {
        self.validate()?;
        let ttl = payload
            .time_to_live_ms
            .ok_or_else(|| eyre::eyre!("native payload has no finite TTL"))?;
        let expiry = payload
            .creation_time_ms
            .checked_add(ttl.get())
            .ok_or_else(|| eyre::eyre!("native payload expiry overflow"))?;
        ensure!(
            payload.network_id() == Some(&self.network)
                && payload.authority == self.authority
                && payload.creation_time_ms > 0
                && self
                    .pin_selected_at_unix_ms
                    .is_none_or(|selected| payload.creation_time_ms >= selected)
                && expiry <= self.authorization.deadline_unix_ms
                && payload.metadata.is_empty()
                && payload.attachments.is_none(),
            "native payload differs from the original identity or finite terms"
        );
        let Executable::Instructions(instructions) = &payload.instructions else {
            eyre::bail!("native pin slot requires one instruction");
        };
        let [instruction] = instructions.as_ref() else {
            eyre::bail!("native pin slot requires one instruction");
        };
        ensure!(
            encode_frame(instruction)? == self.instruction,
            "native payload substituted the selected instruction"
        );
        // Aggregate reservation is recomputed by the root over all original payloads. This
        // local check verifies just the immutable per-transaction component authorization.
        self.authorization.reserve_payload(
            &Default::default(),
            &payload.fee_payment,
            matches!(self.kind, SlotKind::Check(_)),
        )?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PayloadRecord {
    request: [u8; 32],
    payload: String,
}
#[derive(Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SignedRecord {
    request: [u8; 32],
    payload: [u8; 32],
    wire: String,
}
#[derive(Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Retirement {
    request: [u8; 32],
}

/// Local retained slot, including a signed graph awaiting a refused durable write.
/// Even on an error, `signed` remains owned here until exact persistence/reconciliation.
pub(in crate::musubi_publication_service) struct Slot {
    journal: Journal,
    request: SlotRequest,
    signed: Option<SignedTransaction>,
    signed_persisted: Cell<bool>,
}
impl Slot {
    pub(in crate::musubi_publication_service) fn create(
        path: &Path,
        request: SlotRequest,
    ) -> Result<Self> {
        request.validate()?;
        norito::json::to_json_bounded_boxed(&request, 512 * 1024)?;
        let journal = Journal::create_preparation(path, &request)?;
        journal.verify_native_inventory()?;
        Ok(Self {
            journal,
            request,
            signed: None,
            signed_persisted: Cell::new(false),
        })
    }
    pub(in crate::musubi_publication_service) fn open(
        path: &Path,
        expected: &SlotRequest,
    ) -> Result<Self> {
        norito::with_decode_limits_scope(LIMITS, || Self::open_original(path, expected))
    }
    fn open_original(path: &Path, expected: &SlotRequest) -> Result<Self> {
        expected.validate()?;
        let journal = Journal::open(path)?;
        journal.verify_native_inventory()?;
        let request: SlotRequest = journal
            .read_native(NativeRecord::Request)?
            .ok_or_else(|| eyre::eyre!("native pin slot lost its original request"))?;
        ensure!(
            &request == expected,
            "native pin slot changed its original request"
        );
        let mut slot = Self {
            journal,
            request,
            signed: None,
            signed_persisted: Cell::new(false),
        };
        slot.signed = slot.read_durable_signed()?;
        slot.signed_persisted.set(slot.signed.is_some());
        Ok(slot)
    }
    /// Re-read the exact durable prefix under this already-held Journal lock. A valid in-memory
    /// signature can precede its refused durable write, but cannot replace a changed disk record.
    fn revalidate_original(&self) -> Result<()> {
        norito::with_decode_limits_scope(LIMITS, || {
            let durable = self.read_durable_signed()?;
            match (&self.signed, durable) {
                (Some(owned), Some(durable)) => {
                    ensure!(
                        self.signed_record(owned)? == self.signed_record(&durable)?,
                        "held native signature differs from durable original"
                    );
                    self.signed_persisted.set(true);
                }
                (None, Some(_)) => eyre::bail!("held native slot lost its signed original"),
                (Some(owned), None) => {
                    ensure!(
                        !self.signed_persisted.get(),
                        "held native slot lost its persisted signature"
                    );
                    let payload = self
                        .payload()?
                        .ok_or_else(|| eyre::eyre!("held signature lost its payload"))?;
                    self.verify_signed(owned, &payload)?;
                    self.require_unretired()?;
                }
                (None, None) => {}
            }
            Ok(())
        })
    }
    /// Shared decoder for detached reopen and held-owner inspection; neither repairs history.
    fn read_durable_signed(&self) -> Result<Option<SignedTransaction>> {
        self.journal.verify_native_inventory()?;
        let request: SlotRequest = self
            .journal
            .read_native(NativeRecord::Request)?
            .ok_or_else(|| eyre::eyre!("native pin slot lost its original request"))?;
        ensure!(
            request == self.request,
            "native pin slot changed its original request"
        );
        request.validate()?;
        let payload = self.payload()?;
        let signed = if let Some(record) = self
            .journal
            .read_native::<SignedRecord>(NativeRecord::Operation)?
        {
            let payload = payload
                .as_ref()
                .ok_or_else(|| eyre::eyre!("native signed slot lost its payload"))?;
            let wire = decode_hex(&record.wire)?;
            let signed = SignedTransaction::decode_all_versioned(&wire)?;
            self.verify_signed(&signed, payload)?;
            ensure!(
                record == self.signed_record(&signed)?,
                "native signed slot commitments differ"
            );
            self.journal.submission_recorded(&record)?;
            Some(signed)
        } else {
            ensure!(
                !self.journal.has_dispatch_evidence()?,
                "native unsigned slot contains exposure evidence"
            );
            None
        };
        if let Some(retired) = self
            .journal
            .read_native::<Retirement>(NativeRecord::Retired)?
        {
            ensure!(
                payload.is_none() && signed.is_none(),
                "retired native request has later evidence"
            );
            ensure!(
                retired.request == self.request.hash()?,
                "native retirement differs from original request"
            );
        }
        let directory = iroha_fs::PrivateDirectory::open(self.journal.path())?;
        ensure!(
            directory
                .entries(7)?
                .iter()
                .all(|name| name != "applied.json"),
            "native pin slot contains unsupported applied evidence"
        );
        Ok(signed)
    }
    pub(in crate::musubi_publication_service) fn open_retained(path: &Path) -> Result<Self> {
        norito::with_decode_limits_scope(LIMITS, || {
            let journal = Journal::open(path)?;
            let request: SlotRequest = journal
                .read_native(NativeRecord::Request)?
                .ok_or_else(|| eyre::eyre!("native slot has no immutable request"))?;
            drop(journal);
            Self::open(path, &request)
        })
    }
    pub(in crate::musubi_publication_service) fn require_path(
        &self,
        selected: &Path,
    ) -> Result<()> {
        ensure!(
            self.journal.path() == selected,
            "native pin slot directory differs"
        );
        // Reuse the sole phase decoder without reopening our own exclusive lock.
        self.revalidate_original()?;
        Ok(())
    }
    pub(in crate::musubi_publication_service) fn request(&self) -> &SlotRequest {
        &self.request
    }
    pub(in crate::musubi_publication_service) fn payload(
        &self,
    ) -> Result<Option<TransactionPayload>> {
        self.journal.verify_native_inventory()?;
        let Some(record) = self
            .journal
            .read_native::<PayloadRecord>(NativeRecord::Payload)?
        else {
            return Ok(None);
        };
        ensure!(
            record.request == self.request.hash()?,
            "native payload request commitment differs"
        );
        let payload = decode_frame(&record.payload)?;
        self.request.validate_payload(&payload)?;
        Ok(Some(payload))
    }
    pub(in crate::musubi_publication_service) fn retain_payload(
        &self,
        payload: &TransactionPayload,
    ) -> Result<()> {
        self.require_unretired()?;
        self.request.validate_payload(payload)?;
        let record = PayloadRecord {
            request: self.request.hash()?,
            payload: encode_frame(payload)?,
        };
        norito::json::to_json_bounded_boxed(&record, 512 * 1024)?;
        if let Some(retained) = self
            .journal
            .read_native::<PayloadRecord>(NativeRecord::Payload)?
        {
            ensure!(
                retained == record,
                "native payload replacement is forbidden"
            );
        } else {
            self.journal.write_native(NativeRecord::Payload, &record)?;
        }
        Ok(())
    }
    pub(in crate::musubi_publication_service) fn sign_original(
        &mut self,
        key: &KeyPair,
        clock: &mut dyn iroha_musubi_service::MusubiPublicationServiceClockV1,
        deadline: Instant,
    ) -> Result<()> {
        self.require_unretired()?;
        if self.signed.is_none() {
            let payload = self
                .payload()?
                .ok_or_else(|| eyre::eyre!("native payload is not durable"))?;
            let expires_at = payload
                .creation_time_ms
                .checked_add(payload.time_to_live_ms.unwrap().get())
                .ok_or_else(|| eyre::eyre!("original native payload expiry overflow"))?;
            let builder = TransactionBuilder::from_payload(payload)?;
            // Native source reads, payload decoding and builder validation have completed.
            // Sample the durable clock here, immediately before the sole signature operation.
            let now_ms = self
                .request
                .authorization
                .check_effect_boundary(clock, deadline)?;
            ensure!(now_ms < expires_at, "original native payload has expired");
            // The exact payload is already durable. A backend refusal cannot renew it.
            let signed = builder.try_sign(key.private_key())?;
            self.signed = Some(signed); // retain before any encoding, I/O or finality check can fail.
        }
        self.persist_signed()
    }
    pub(in crate::musubi_publication_service) fn signed_commitment(
        &self,
    ) -> Result<Option<[u8; 32]>> {
        self.signed
            .as_ref()
            .map(|signed| {
                Ok(Sha256::digest(norito::json::to_json_bounded_boxed(
                    &self.signed_record(signed)?,
                    512 * 1024,
                )?)
                .into())
            })
            .transpose()
    }
    pub(in crate::musubi_publication_service) fn signed(&self) -> Option<&SignedTransaction> {
        self.signed.as_ref()
    }
    pub(in crate::musubi_publication_service) fn persist_signed(&self) -> Result<()> {
        let signed = self
            .signed
            .as_ref()
            .ok_or_else(|| eyre::eyre!("native slot has no signature"))?;
        let payload = self
            .payload()?
            .ok_or_else(|| eyre::eyre!("native slot lost its payload"))?;
        self.verify_signed(signed, &payload)?;
        let record = self.signed_record(signed)?;
        norito::json::to_json_bounded_boxed(&record, 512 * 1024)?;
        if let Some(original) = self
            .journal
            .read_native::<SignedRecord>(NativeRecord::Operation)?
        {
            ensure!(original == record, "native signed replacement is forbidden");
        } else {
            self.journal
                .write_native(NativeRecord::Operation, &record)?;
        }
        self.signed_persisted.set(true);
        Ok(())
    }
    fn verify_signed(
        &self,
        signed: &SignedTransaction,
        payload: &TransactionPayload,
    ) -> Result<()> {
        self.request.validate_payload(payload)?;
        ensure!(
            signed.payload() == payload && signed.multisig_signatures().is_none(),
            "native original signature or payload differs"
        );
        // Preserve original canonical hashing/resource refusal before classifying a completed
        // signature rejection. The ordinary facade formats this failure and is not used here.
        let signatory = payload
            .authority
            .try_signatory()
            .ok_or_else(|| eyre::eyre!("native original authority is not direct"))?;
        let hash = iroha_crypto::HashOf::try_new(payload)?;
        iroha_crypto::verify_signature_borrowed(&signed.signature().0, signatory, hash.as_ref())
            .map_err(|_| eyre::eyre!("native original signature differs"))?;
        Ok(())
    }
    fn signed_record(&self, signed: &SignedTransaction) -> Result<SignedRecord> {
        let payload = encode_frame(signed.payload())?;
        let wire = signed.wire_plan_v1()?.into_vec_bounded(MAX_FRAME_BYTES)?;
        Ok(SignedRecord {
            request: self.request.hash()?,
            payload: Sha256::digest(payload.as_bytes()).into(),
            wire: encode_hex(&wire)?,
        })
    }
    /// Durable exposure is the last local operation before the owning coordinator's Queue call.
    /// Only true permits that one call; false permanently requires read-only reconciliation.
    pub(in crate::musubi_publication_service) fn record_exposure(&self) -> Result<bool> {
        self.require_unretired()?;
        self.persist_signed()?;
        let record = self.signed_record(self.signed.as_ref().unwrap())?;
        self.journal.record_submission(&record)
    }
    /// Move the exact retained graph into ordinary admission only after the caller has durably
    /// exposed this slot. Consuming the whole slot prevents a moved graph from appearing unsigned.
    pub(in crate::musubi_publication_service) fn into_exposed_transaction(
        mut self,
    ) -> Result<SignedTransaction> {
        ensure!(
            self.exposed()?,
            "native transaction has no durable exposure"
        );
        self.signed
            .take()
            .ok_or_else(|| eyre::eyre!("native slot lost its signed original"))
    }
    pub(in crate::musubi_publication_service) fn exposed(&self) -> Result<bool> {
        let Some(signed) = &self.signed else {
            return Ok(false);
        };
        self.journal
            .submission_recorded(&self.signed_record(signed)?)
    }
    pub(in crate::musubi_publication_service) fn retire_request_only(&self) -> Result<()> {
        self.journal.verify_native_inventory()?;
        ensure!(
            self.payload()?.is_none() && self.signed.is_none(),
            "native request already has payload/signature custody"
        );
        ensure!(
            !self.journal.has_dispatch_evidence()?,
            "native request has exposure evidence"
        );
        let record = Retirement {
            request: self.request.hash()?,
        };
        if let Some(old) = self
            .journal
            .read_native::<Retirement>(NativeRecord::Retired)?
        {
            ensure!(old == record, "native retirement original differs");
        } else {
            self.journal.write_native(NativeRecord::Retired, &record)?;
        }
        Ok(())
    }
    fn require_unretired(&self) -> Result<()> {
        self.journal.verify_native_inventory()?;
        ensure!(
            self.journal
                .read_native::<Retirement>(NativeRecord::Retired)?
                .is_none(),
            "original native request retired"
        );
        Ok(())
    }
}

pub(in crate::musubi_publication_service) fn encode_frame<T: norito::core::NoritoSerialize>(
    value: &T,
) -> Result<String> {
    let length = norito::canonical_frame_len(value)?;
    ensure!(
        length <= MAX_FRAME_BYTES,
        "native slot frame exceeds its bound"
    );
    let bytes = norito::core::to_bytes_bounded(value, length)
        .map_err(|error| match error {
            norito::core::BoundedEncodeError::Serialization(error)
                if error.decode_resource_error().is_some() => eyre::Report::from(error),
            error => eyre::Report::from(error),
        })?;
    encode_hex(&bytes)
}
pub(in crate::musubi_publication_service) fn decode_frame<T>(text: &str) -> Result<T>
where
    T: norito::core::NoritoSerialize + for<'a> norito::core::NoritoDeserialize<'a>,
{
    norito::with_decode_limits_scope(LIMITS, || {
        let bytes = decode_hex(text)?;
        Ok(norito::decode_canonical(&bytes)?)
    })
}
fn encode_hex(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len() <= MAX_FRAME_BYTES,
        "native slot bytes exceed their bound"
    );
    let length = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| eyre::eyre!("native hex extent overflow"))?;
    norito::core::reserve_decode_allocation(length)?;
    let mut output = Vec::new();
    output.try_reserve_exact(length)?;
    output.resize(length, 0);
    hex::encode_to_slice(bytes, &mut output)?;
    Ok(String::from_utf8(output)?)
}
fn decode_hex(text: &str) -> Result<Vec<u8>> {
    ensure!(
        !text.is_empty()
            && text.len() % 2 == 0
            && text.len() / 2 <= MAX_FRAME_BYTES
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native slot has noncanonical or oversized hex"
    );
    let length = text.len() / 2;
    norito::core::reserve_decode_allocation(length)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
#[path = "slot_tests.rs"]
mod tests;
