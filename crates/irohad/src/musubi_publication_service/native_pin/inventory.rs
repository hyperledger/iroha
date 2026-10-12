//! Complete portable native pin inventory under the shared operation-journal lock.
//!
//! Every original and control directory is inspected. The anchored digest commits the original
//! session and all exact signed pin records; Check/Advance records are fully audited and charged
//! to their original operation, but cannot recursively change the inventory they authenticate.
//! This local digest is a custody claim. Only the native Check/Advance owners authenticate it.

use super::super::MusubiPublicationFinalizedArchiveRegistrationQueryV1;
use super::{
    authorization::{NativePinAuthorizationV1, ReservedFeesV1},
    slot::{self, Slot, SlotKind, SlotRequest},
};
use eyre::{Result, ensure};
use iroha_data_model::transaction::TransactionPayload;
use iroha_fs::{FileSnapshot, PrivateDirectory};
use iroha_musubi_service::NativeMusubiPinSessionV1;
use iroha_operation_journal::{Journal, NativeRecord};
use norito::json::{JsonDeserialize, JsonSerialize};
use sha2::{Digest as _, Sha256};
use std::{ffi::OsStr, io::Read as _, path::Path};

const MAX_OPERATIONS: usize = 64;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
// A new immutable directory reserves its complete bounded future record footprint before it
// exists. This is a storage limit (not an allocation charge); failed/retired slots keep it.
const ROOT_BYTES: u64 = 8192;
const OPERATION_BYTES: u64 = 512 * 1024 + 1024;
const SLOT_BYTES: u64 = 3 * 512 * 1024 + 1024;
const MAX_OPERATION_FILES: usize = 3 + 3 + 16;

#[derive(Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct Operation {
    pub(super) id: [u8; 32],
    pub(super) ordinal: u32,
    /// Exact complete caller intent digest; local claims only.
    pub(super) context_digest: [u8; 32],
    /// Existing canonical finalized archive query frame; this record grants no finality.
    pub(super) source: String,
    pub(super) authorization: NativePinAuthorizationV1,
}
impl Operation {
    fn validate(&self, original: &NativeMusubiPinSessionV1) -> Result<()> {
        ensure!(
            self.id != [0; 32]
                && self.context_digest != [0; 32]
                && (1..=MAX_OPERATIONS as u32).contains(&self.ordinal),
            "native pin operation coordinates are invalid"
        );
        self.authorization.validate()?;
        let source: MusubiPublicationFinalizedArchiveRegistrationQueryV1 =
            slot::decode_frame(&self.source)?;
        ensure!(
            source.network_id == original.network && source.version == 1,
            "native pin source original differs"
        );
        norito::json::to_json_bounded_boxed(self, 512 * 1024)?;
        Ok(())
    }
    pub(super) fn source(&self) -> Result<MusubiPublicationFinalizedArchiveRegistrationQueryV1> {
        slot::decode_frame(&self.source)
    }
}

#[derive(PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Retirement {
    operation: [u8; 32],
}
fn operation_commitment(operation: &Operation) -> Result<[u8; 32]> {
    Ok(Sha256::digest(norito::json::to_json_bounded_boxed(operation, 512 * 1024)?).into())
}

/// Complete local observation, never a current-state or transaction-success capability.
pub(super) struct Inventory {
    pub(super) digest: [u8; 32],
    pub(super) signed_pins: u32,
    pub(super) operations: u32,
    pub(super) bytes: u64,
    pub(super) reserved_bytes: u64,
}

/// One authority-wide retained session. No ordinary open creates a directory or missing record.
pub(super) struct Store {
    journal: Journal,
    directory: PrivateDirectory,
    original: NativeMusubiPinSessionV1,
}
impl Store {
    pub(super) fn initialize(path: &Path, original: NativeMusubiPinSessionV1) -> Result<Self> {
        original.validate()?;
        let journal = original.initialize_private_journal(path)?;
        let directory = PrivateDirectory::open(journal.path())?;
        let store = Self {
            journal,
            directory,
            original,
        };
        store.inventory(None)?;
        Ok(store)
    }
    pub(super) fn open(path: &Path, expected: &NativeMusubiPinSessionV1) -> Result<Self> {
        expected.validate()?;
        let journal = Journal::open(path)?;
        let original: NativeMusubiPinSessionV1 = journal.read_operation()?;
        ensure!(
            &original == expected,
            "native pin session changed its original policy or identity"
        );
        original.validate()?;
        let directory = PrivateDirectory::open(journal.path())?;
        let store = Self {
            journal,
            directory,
            original,
        };
        store.inventory(None)?;
        Ok(store)
    }
    pub(super) fn original(&self) -> &NativeMusubiPinSessionV1 {
        &self.original
    }

    /// Inspect all original requests, payloads, signatures and exposure markers, including a
    /// possibly pending pin. Exclusion reconstructs only the exact selected predecessor digest;
    /// the excluded operation's entire custody and authorization is still audited.
    pub(super) fn inventory(&self, excluding: Option<[u8; 32]>) -> Result<Inventory> {
        self.inventory_with_held(excluding, None)
    }
    fn inventory_with_held(
        &self,
        excluding: Option<[u8; 32]>,
        held: Option<&Slot>,
    ) -> Result<Inventory> {
        self.directory.revalidate()?;
        ensure!(
            self.journal.read_operation::<NativeMusubiPinSessionV1>()? == self.original,
            "native pin owner evidence differs"
        );
        let mut digest = Sha256::new();
        digest.update(b"iroha/native-musubi-pin-inventory/v1\0");
        hash_record(&mut digest, &self.original)?;
        let mut bytes = 0u64;
        let mut operations = 0u32;
        let mut signed_pins = 0u32;
        let mut reserved_bytes = ROOT_BYTES;
        let mut ordinals = [false; MAX_OPERATIONS];
        let mut excluded = false;
        let mut found_held = false;
        for name in self.directory.entries(MAX_OPERATIONS + 2)? {
            if name == "lock" || name == "operation.json" {
                account_file(&self.directory, &name, &mut bytes)?;
                continue;
            }
            let id = operation_name(&name)?;
            let directory = self.directory.open_child(&name)?;
            let journal = Journal::open(directory.path())?;
            let operation: Operation = journal.read_operation()?;
            operation.validate(&self.original)?;
            ensure!(
                operation.id == id && !ordinals[(operation.ordinal - 1) as usize],
                "native pin operation identity or ordinal differs"
            );
            ordinals[(operation.ordinal - 1) as usize] = true;
            operations += 1;
            drop(journal);
            let audit = self.audit_operation(&directory, &operation, &mut bytes, held)?;
            found_held |= audit.held;
            reserved_bytes = reserved_bytes
                .checked_add(OPERATION_BYTES)
                .and_then(|bytes| bytes.checked_add(u64::from(audit.slots) * SLOT_BYTES))
                .ok_or_else(|| eyre::eyre!("native pin inventory reservation overflow"))?;
            ensure!(
                reserved_bytes <= MAX_TOTAL_BYTES,
                "native pin original storage reservation exceeds capacity"
            );
            if excluding == Some(id) {
                ensure!(
                    audit.signed.is_some(),
                    "excluded native pin has no exact original signature"
                );
                excluded = true;
            } else if let Some(signed) = audit.signed {
                hash_record(&mut digest, &operation)?;
                digest.update(signed);
                signed_pins += 1;
            }
        }
        ensure!(
            ordinals[..operations as usize]
                .iter()
                .all(|present| *present),
            "native pin original operation inventory has a gap"
        );
        ensure!(
            excluding.is_none() || excluded,
            "excluded native operation is missing"
        );
        ensure!(
            held.is_none() || found_held,
            "held native slot is absent from original inventory"
        );
        self.directory.revalidate()?;
        Ok(Inventory {
            digest: digest.finalize().into(),
            signed_pins,
            operations,
            bytes,
            reserved_bytes,
        })
    }

    pub(super) fn create_operation(&self, operation: &Operation) -> Result<()> {
        operation.validate(&self.original)?;
        let before = self.inventory(None)?;
        ensure!(
            before.operations < MAX_OPERATIONS as u32 && operation.ordinal == before.operations + 1,
            "native pin operation inventory is full or nonsequential"
        );
        ensure!(
            before
                .reserved_bytes
                .checked_add(OPERATION_BYTES)
                .is_some_and(|bytes| bytes <= MAX_TOTAL_BYTES),
            "native pin original storage capacity is exhausted"
        );
        let name = format!("op-{}", hex::encode(operation.id));
        drop(Journal::create_prepared(
            &self.directory.path().join(name),
            operation,
        )?);
        self.inventory(None)?;
        Ok(())
    }
    pub(super) fn find_operation(&self, id: [u8; 32]) -> Result<Option<Operation>> {
        self.find_operation_with_held(id, None)
    }
    pub(super) fn find_operation_with_held(
        &self,
        id: [u8; 32],
        held: Option<&Slot>,
    ) -> Result<Option<Operation>> {
        self.inventory_with_held(None, held)?;
        let name = format!("op-{}", hex::encode(id));
        if !self
            .directory
            .entries(MAX_OPERATIONS + 2)?
            .iter()
            .any(|entry| entry == name.as_str())
        {
            return Ok(None);
        }
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(id)))?;
        let journal = Journal::open(directory.path())?;
        let operation: Operation = journal.read_operation()?;
        operation.validate(&self.original)?;
        ensure!(operation.id == id, "native original operation differs");
        Ok(Some(operation))
    }
    pub(super) fn retire_operation(&self, operation: &Operation) -> Result<()> {
        self.inventory(None)?;
        self.require_original_operation(operation)?;
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(operation.id)))?;
        let journal = Journal::open(directory.path())?;
        let record = Retirement {
            operation: operation_commitment(operation)?,
        };
        if let Some(retained) = journal.read_native::<Retirement>(NativeRecord::Retired)? {
            ensure!(retained == record, "native operation retirement differs");
        } else {
            journal.write_native(NativeRecord::Retired, &record)?;
        }
        Ok(())
    }
    pub(super) fn require_active_operation(&self, operation: &Operation) -> Result<()> {
        self.require_original_operation(operation)?;
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(operation.id)))?;
        let journal = Journal::open(directory.path())?;
        ensure!(
            journal
                .read_native::<Retirement>(NativeRecord::Retired)?
                .is_none(),
            "original native pin authorization retired; read-only recovery only"
        );
        Ok(())
    }
    pub(super) fn operation(&self, id: [u8; 32]) -> Result<Operation> {
        self.inventory(None)?;
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(id)))?;
        let journal = Journal::open(directory.path())?;
        let operation: Operation = journal.read_operation()?;
        operation.validate(&self.original)?;
        ensure!(operation.id == id, "native pin original differs");
        Ok(operation)
    }
    pub(super) fn slot_path(
        &self,
        operation: &Operation,
        kind: SlotKind,
    ) -> Result<std::path::PathBuf> {
        operation.validate(&self.original)?;
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(operation.id)))?;
        Ok(directory.path().join(slot_name(kind)))
    }
    pub(super) fn open_slot(&self, operation: &Operation, kind: SlotKind) -> Result<Option<Slot>> {
        self.require_original_operation(operation)?;
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(operation.id)))?;
        let name = slot_name(kind);
        if !directory
            .entries(MAX_OPERATION_FILES)?
            .iter()
            .any(|entry| entry == name.as_str())
        {
            return Ok(None);
        }
        let slot = Slot::open_retained(directory.open_child(&name)?.path())?;
        self.validate_slot(operation, slot.request())?;
        ensure!(
            slot.request().kind == kind,
            "native selected slot purpose differs"
        );
        Ok(Some(slot))
    }
    pub(super) fn next_check_round(&self, operation: &Operation) -> Result<u16> {
        self.inventory(None)?;
        self.require_original_operation(operation)?;
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(operation.id)))?;
        let mut last = 0;
        for name in directory.entries(MAX_OPERATION_FILES)? {
            if name == "lock" || name == "operation.json" || name == "retired.json" {
                continue;
            }
            if let SlotKind::Check(round) = parse_slot_name(&name)? {
                last = last.max(round);
            }
        }
        let next = last
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("native round overflow"))?;
        ensure!(
            next <= operation.authorization.max_check_rounds,
            "original native Check round allowance is exhausted"
        );
        Ok(next)
    }
    pub(super) fn create_slot(&self, operation: &Operation, request: SlotRequest) -> Result<Slot> {
        let before = self.inventory(None)?;
        ensure!(
            before
                .reserved_bytes
                .checked_add(SLOT_BYTES)
                .is_some_and(|bytes| bytes <= MAX_TOTAL_BYTES),
            "native pin complete slot storage capacity is exhausted"
        );
        self.require_original_operation(operation)?;
        self.validate_slot(operation, &request)?;
        self.require_active_operation(operation)?;
        Slot::create(&self.slot_path(operation, request.kind)?, request)
    }

    /// Recompute the complete worst-case fee reservation before appending a quoted payload.
    /// Existing payloads are never refunded on a failed signature, missing result or Queue error.
    pub(super) fn admit_payload(
        &self,
        operation: &Operation,
        candidate: &Slot,
        payload: &TransactionPayload,
    ) -> Result<()> {
        self.require_active_operation(operation)?;
        self.validate_slot(operation, candidate.request())?;
        candidate.require_path(&self.slot_path(operation, candidate.request().kind)?)?;
        // The selected candidate is already locked by its caller. Audit the remaining fixed
        // slots directly and include that candidate's original retained payload exactly once.
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(operation.id)))?;
        let mut fees = ReservedFeesV1::default();
        for name in directory.entries(MAX_OPERATION_FILES)? {
            if name == "lock" || name == "operation.json" || name == "retired.json" {
                continue;
            }
            let kind = parse_slot_name(&name)?;
            if kind == candidate.request().kind {
                continue;
            }
            let retained = Slot::open_retained(directory.open_child(&name)?.path())?;
            self.validate_slot(operation, retained.request())?;
            ensure!(
                retained.request().kind == kind,
                "native pin slot filename differs from its original purpose"
            );
            if let Some(payload) = retained.payload()? {
                fees = operation.authorization.reserve_payload(
                    &fees,
                    &payload.fee_payment,
                    matches!(kind, SlotKind::Check(_)),
                )?;
            }
        }
        if let Some(original) = candidate.payload()? {
            ensure!(
                &original == payload,
                "native pin quoted payload is immutable"
            );
        }
        operation.authorization.reserve_payload(
            &fees,
            &payload.fee_payment,
            matches!(candidate.request().kind, SlotKind::Check(_)),
        )?;
        Ok(())
    }

    fn require_original_operation(&self, operation: &Operation) -> Result<()> {
        let directory = self
            .directory
            .open_child(format!("op-{}", hex::encode(operation.id)))?;
        let journal = Journal::open(directory.path())?;
        ensure!(
            &journal.read_operation::<Operation>()? == operation,
            "native pin original operation was substituted"
        );
        Ok(())
    }
    fn validate_slot(&self, operation: &Operation, request: &SlotRequest) -> Result<()> {
        let storage_class = match self.original.storage_class {
            0 => iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
            1 => iroha_data_model::sorafs::pin_registry::StorageClass::Warm,
            2 => iroha_data_model::sorafs::pin_registry::StorageClass::Cold,
            _ => eyre::bail!("native pin original storage class differs"),
        };
        request.validate_pin_policy(storage_class, self.original.retention_horizon_secs)?;
        ensure!(
            request.network == self.original.network
                && request.authority == self.original.authority
                && request.session == self.original.session
                && request.operation == operation.id
                && request.authorization == operation.authorization,
            "native pin control changed its original operation binding"
        );
        Ok(())
    }
    fn audit_operation(
        &self,
        directory: &PrivateDirectory,
        operation: &Operation,
        bytes: &mut u64,
        held: Option<&Slot>,
    ) -> Result<OperationAudit> {
        let journal = Journal::open(directory.path())?;
        if let Some(retired) = journal.read_native::<Retirement>(NativeRecord::Retired)? {
            ensure!(
                retired.operation == operation_commitment(operation)?,
                "native operation retirement differs"
            );
        }
        drop(journal);
        let mut fees = ReservedFeesV1::default();
        let mut signed = None;
        let mut slots = 0u32;
        let mut rounds = [false; 16];
        let mut found_held = false;
        for name in directory.entries(MAX_OPERATION_FILES)? {
            if name == "lock" || name == "operation.json" || name == "retired.json" {
                account_file(directory, &name, bytes)?;
                continue;
            }
            let kind = parse_slot_name(&name)?;
            slots += 1;
            let selected = directory.open_child(&name)?;
            for file in selected.entries(7)? {
                account_file(&selected, &file, bytes)?;
            }
            let opened;
            let slot = if let Some(held) = held.filter(|slot| {
                slot.request().operation == operation.id && slot.request().kind == kind
            }) {
                held.require_path(selected.path())?;
                found_held = true;
                held
            } else {
                opened = Slot::open_retained(selected.path())?;
                &opened
            };
            self.validate_slot(operation, slot.request())?;
            ensure!(
                slot.request().kind == kind,
                "native pin control filename differs"
            );
            if let SlotKind::Check(round) = kind {
                rounds[usize::from(round - 1)] = true;
            }
            if let Some(payload) = slot.payload()? {
                fees = operation.authorization.reserve_payload(
                    &fees,
                    &payload.fee_payment,
                    matches!(kind, SlotKind::Check(_)),
                )?;
            }
            if kind == SlotKind::Pin {
                signed = slot.signed_commitment()?;
            }
        }
        if let Some(last) = rounds.iter().rposition(|present| *present) {
            ensure!(
                rounds[..=last].iter().all(|present| *present),
                "native Check round inventory has a gap"
            );
        }
        directory.revalidate()?;
        Ok(OperationAudit {
            signed,
            slots,
            held: found_held,
        })
    }
}
struct OperationAudit {
    held: bool,
    signed: Option<[u8; 32]>,
    slots: u32,
}

fn slot_name(kind: SlotKind) -> String {
    match kind {
        SlotKind::Pin => "pin".to_owned(),
        SlotKind::Initialize => "initialize".to_owned(),
        SlotKind::Advance => "advance".to_owned(),
        SlotKind::Check(round) => format!("check-{round:02}"),
    }
}
fn parse_slot_name(name: &OsStr) -> Result<SlotKind> {
    match name.to_str() {
        Some("pin") => Ok(SlotKind::Pin),
        Some("initialize") => Ok(SlotKind::Initialize),
        Some("advance") => Ok(SlotKind::Advance),
        Some(value) if value.starts_with("check-") => {
            let round: u16 = value[6..].parse()?;
            ensure!(
                (1..=16).contains(&round) && value == slot_name(SlotKind::Check(round)),
                "native Check name is not canonical"
            );
            Ok(SlotKind::Check(round))
        }
        _ => eyre::bail!("unknown native pin control inventory member"),
    }
}
fn operation_name(name: &OsStr) -> Result<[u8; 32]> {
    let text = name
        .to_str()
        .and_then(|name| name.strip_prefix("op-"))
        .ok_or_else(|| eyre::eyre!("unknown native pin session inventory member"))?;
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native operation name is not canonical"
    );
    let mut id = [0; 32];
    hex::decode_to_slice(text, &mut id)?;
    ensure!(id != [0; 32], "native operation ID is zero");
    Ok(id)
}
fn hash_record<T: JsonSerialize>(hash: &mut Sha256, value: &T) -> Result<()> {
    let bytes = norito::json::to_json_bounded_boxed(value, 512 * 1024)?;
    hash.update(u64::try_from(bytes.len())?.to_le_bytes());
    hash.update(bytes);
    Ok(())
}
fn account_file(directory: &PrivateDirectory, name: &OsStr, bytes: &mut u64) -> Result<()> {
    let mut file = directory.open_read(name)?;
    let before = FileSnapshot::of(&file, true)?;
    let length = file.metadata()?.len();
    ensure!(
        name != "lock" || length == 0,
        "native journal lock has unexpected content"
    );
    ensure!(
        length <= 4 * 1024 * 1024,
        "native journal record exceeds bound"
    );
    *bytes = bytes
        .checked_add(length)
        .filter(|total| *total <= MAX_TOTAL_BYTES)
        .ok_or_else(|| eyre::eyre!("native complete journal inventory exceeds bound"))?;
    // The owning Journal decodes semantic records. This pass also validates exact physical EOF,
    // without allocating a second whole-file buffer. An exact empty lock needs no body read:
    // Windows byte-range locks can refuse a read through this separately opened handle.
    let mut remaining = length;
    let mut chunk = [0; 8192];
    while remaining > 0 {
        let n = usize::try_from(remaining.min(chunk.len() as u64))?;
        file.read_exact(&mut chunk[..n])?;
        remaining -= n as u64;
    }
    let mut tail = [0];
    ensure!(
        (name == "lock" || file.read(&mut tail)? == 0) && FileSnapshot::of(&file, true)? == before,
        "native journal file changed during inventory"
    );
    let current = directory.open_read(name)?;
    ensure!(
        FileSnapshot::of(&current, true)? == before,
        "native journal file namespace changed"
    );
    Ok(())
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
