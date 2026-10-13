//! Exact current and predecessor records for stores with compound binary keys.

use super::deserialize::StateRestoreError;
use super::*;
use norito::codec::DecodeAll;
use norito::json::JsonSerialize as _;

/// Validate every retained manifest against both storage coordinates and its bytes.
pub(super) fn manifest_set_matches_key(
    uaid: &UniversalAccountId,
    manifests: &SpaceDirectoryManifestSet,
) -> bool {
    manifests.iter().all(|(dataspace, record)| {
        record.uaid() == *uaid
            && record.dataspace() == *dataspace
            && record.manifest_hash == Hash::from(HashOf::new(&record.manifest))
    })
}

/// Mandatory current/undo envelope; first-release snapshots have one wire shape.
#[derive(JsonSerialize, JsonDeserialize)]
pub(crate) struct SnapshotStorage {
    revert: Vec<SnapshotStorageUndo>,
    blocks: Vec<SnapshotStorageEntry>,
}

#[derive(JsonSerialize, JsonDeserialize)]
struct SnapshotStorageEntry {
    key: SnapshotNoritoBlob,
    value: SnapshotNoritoBlob,
}

#[derive(JsonSerialize, JsonDeserialize)]
struct SnapshotStorageUndo {
    key: SnapshotNoritoBlob,
    value: Option<SnapshotNoritoBlob>,
}

fn blob(value: &impl Encode) -> SnapshotNoritoBlob {
    SnapshotNoritoBlob {
        encoded_hex: hex::encode(value.encode()),
    }
}

fn serialize_maps<'a, K: mv::Key + Encode, V: mv::Value + Encode>(
    revert: impl Iterator<Item = (&'a K, &'a Option<V>)>,
    current: impl Iterator<Item = (&'a K, &'a V)>,
    out: &mut String,
) {
    out.push_str("{\"revert\":[");
    for (index, (key, value)) in revert.enumerate() {
        if index != 0 {
            out.push(',');
        }
        SnapshotStorageUndo {
            key: blob(key),
            value: value.as_ref().map(blob),
        }
        .json_serialize(out);
    }
    out.push_str("],\"blocks\":[");
    for (index, (key, value)) in current.enumerate() {
        if index != 0 {
            out.push(',');
        }
        SnapshotStorageEntry {
            key: blob(key),
            value: blob(value),
        }
        .json_serialize(out);
    }
    out.push_str("]}");
}

/// Encode borrowed MV maps under the caller's State publication generation fence.
pub(crate) fn serialize<
    K: mv::Key + Encode,
    V: mv::Value + Encode,
    M: mv::storage::StorageMode<K, V>,
>(
    store: &Storage<K, V, M>,
    out: &mut String,
) {
    let snapshot = store.snapshot();
    serialize_maps(snapshot.revert_map().iter(), snapshot.current().iter(), out);
}

/// Encode the exact staged post-commit maps without losing their original undo.
#[cfg(test)]
pub(crate) fn serialize_block<
    K: mv::Key + Encode,
    V: mv::Value + Encode,
    M: mv::storage::StorageMode<K, V>,
>(
    store: &block_field::StorageField<'_, K, V, M>,
    out: &mut String,
) {
    serialize_maps(store.original_undo_entries(), store.iter(), out);
}

pub(super) fn decode_blob<T: DecodeAll + Encode>(
    record: SnapshotNoritoBlob,
    field: &str,
) -> Result<T, json::Error> {
    let invalid = |message| json::Error::InvalidField {
        field: field.to_owned(),
        message,
    };
    let bytes = hex::decode(&record.encoded_hex)
        .map_err(|error| invalid(format!("invalid Norito hex: {error}")))?;
    if hex::encode(&bytes) != record.encoded_hex {
        return Err(invalid("noncanonical Norito hex".to_owned()));
    }
    let decoded = T::decode_all(&mut bytes.as_slice())
        .map_err(|error| invalid(format!("invalid Norito record: {error}")))?;
    if decoded.encode() != bytes {
        return Err(invalid("record is not canonical Norito".to_owned()));
    }
    Ok(decoded)
}

impl SnapshotStorage {
    /// Decode closed fixed-copy reconciliation rows directly into original admitted maps.
    /// No intermediate untracked tree or attacker-sized binary buffer is constructed.
    pub(super) fn decode_reconciliation_fixed<K, V>(
        self,
        field: &'static str,
        budget: &iroha_allocation::AllocationBudget,
        valid: impl Fn(&K, &V) -> bool,
    ) -> Result<
        mv::storage::Storage<K, V, crate::smartcontracts::isi::sccp::reconciliation_store::Mode>,
        StateRestoreError,
    >
    where
        K: mv::Key + Copy + norito::codec::DecodeAll + norito::codec::Encode,
        V: mv::Value + Copy + norito::codec::DecodeAll + norito::codec::Encode,
        crate::smartcontracts::isi::sccp::reconciliation_store::ReconciliationStoragePolicy:
            concread::bptree::NodeCloning<K, V>
                + concread::bptree::ClonePlanning<K, V>
                + concread::bptree::NodeCloning<K, Option<V>>
                + concread::bptree::ClonePlanning<K, Option<V>>,
    {
        fn invalid(field: &str, message: &str) -> StateRestoreError {
            json::Error::InvalidField {
                field: field.into(),
                message: message.into(),
            }
            .into()
        }
        fn decode<T: norito::codec::DecodeAll + norito::codec::Encode>(
            blob: SnapshotNoritoBlob,
            field: &str,
        ) -> Result<T, StateRestoreError> {
            // All admitted key/value types in this closed policy are fixed-size and their
            // canonical bare Norito representations fit this checked 512-byte envelope.
            let text = blob.encoded_hex;
            if text.len() > 1024
                || !text.len().is_multiple_of(2)
                || text
                    .bytes()
                    .any(|b| !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(invalid(field, "noncanonical or excessive fixed record hex"));
            }
            let mut bytes = [0u8; 512];
            let bytes = &mut bytes[..text.len() / 2];
            hex::decode_to_slice(&text, bytes)
                .map_err(|_| invalid(field, "invalid fixed record hex"))?;
            let codec = |error: norito::Error| {
                error.decode_resource_error().map_or_else(
                    || invalid(field, "invalid fixed record payload"),
                    |original| {
                        StateRestoreError::Sccp(
                            sccp_snapshot_state::SccpRestoreError::ReconciliationDecode(original),
                        )
                    },
                )
            };
            let value = T::decode_all(&mut &*bytes).map_err(codec)?;
            norito::codec::verify_exact_payload(&value, bytes).map_err(codec)?;
            Ok(value)
        }
        mv::storage::Storage::<K,V,crate::smartcontracts::isi::sccp::reconciliation_store::Mode>::try_restore_admitted(budget.clone(), |current, undo| {
            let mut last = None;
            for row in self.blocks {
                let key: K = decode(row.key, field)?;
                let value: V = decode(row.value, field)?;
                if last.is_some_and(|last| last >= key) || !valid(&key, &value) { return Err(invalid(field, "unordered or invalid current fixed record")); }
                last = Some(key);
                current(key, value)?;
            }
            last = None;
            for row in self.revert {
                let key: K = decode(row.key, field)?;
                let value: Option<V> = row.value.map(|blob| decode(blob, field)).transpose()?;
                if last.is_some_and(|last| last >= key) || value.as_ref().is_some_and(|value| !valid(&key, value)) { return Err(invalid(field, "unordered or invalid undo fixed record")); }
                last = Some(key);
                undo(key, value)?;
            }
            Ok::<(), StateRestoreError>(())
        }).map_err(|error| match error {
            mv::storage::AdmittedBlockError::Admission(original) => StateRestoreError::Sccp(sccp_snapshot_state::SccpRestoreError::Storage(original)),
            mv::storage::AdmittedBlockError::Callback(original) => original,
        })
    }

    pub(super) fn decode<K, V>(
        self,
        field: &str,
        matches_key: impl Fn(&K, &V) -> bool,
    ) -> Result<Storage<K, V>, json::Error>
    where
        K: mv::Key + DecodeAll + Encode,
        V: mv::Value + DecodeAll + Encode,
    {
        let invalid = |message| json::Error::InvalidField {
            field: field.to_owned(),
            message,
        };
        let mut revert = BTreeMap::new();
        for record in self.revert {
            let key: K = decode_blob(record.key, field)?;
            if revert
                .last_key_value()
                .is_some_and(|(last, _)| last >= &key)
            {
                return Err(invalid(
                    "undo records are not in strict semantic key order".to_owned(),
                ));
            }
            let value = record
                .value
                .map(|value| decode_blob::<V>(value, field))
                .transpose()?;
            if value
                .as_ref()
                .is_some_and(|value| !matches_key(&key, value))
            {
                return Err(invalid("undo record does not match its key".to_owned()));
            }
            revert.insert(key, value);
        }
        let mut blocks = BTreeMap::new();
        for record in self.blocks {
            let key: K = decode_blob(record.key, field)?;
            if blocks
                .last_key_value()
                .is_some_and(|(last, _)| last >= &key)
            {
                return Err(invalid(
                    "current records are not in strict semantic key order".to_owned(),
                ));
            }
            let value: V = decode_blob(record.value, field)?;
            if !matches_key(&key, &value) {
                return Err(invalid("current record does not match its key".to_owned()));
            }
            blocks.insert(key, value);
        }
        Ok(Storage::from_snapshot_parts(blocks, revert))
    }
}

#[cfg(test)]
#[path = "snapshot_storage_tests.rs"]
mod tests;

impl SnapshotStorage {
    /// Restore exact current and undo entries directly into private admitted maps.
    /// The input JSON envelope belongs to the caller; every new record graph and
    /// current/undo map allocation comes from this unchanged original store pool.
    pub(crate) fn decode_generations(
        self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<
        crate::smartcontracts::isi::sccp::committee_storage::CommitteeStorage,
        StateRestoreError,
    > {
        use crate::smartcontracts::isi::sccp::{
            committee_storage::CommitteeStorage,
            generation_record::{GenerationRecordError, RetainedSccpGeneration},
        };
        fn invalid(message: &str) -> StateRestoreError {
            json::Error::InvalidField {
                field: "sccp_committee_generations".into(),
                message: message.into(),
            }
            .into()
        }
        fn key(blob: SnapshotNoritoBlob) -> Result<u64, StateRestoreError> {
            // Fixed V1 u64 payload is exactly eight bytes. Reject alternate hex
            // and canonical Norito spellings without allocating a scratch Vec.
            let mut bytes = [0u8; 8];
            if blob.encoded_hex.len() != 16
                || blob
                    .encoded_hex
                    .bytes()
                    .any(|b| !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(invalid("noncanonical generation key hex"));
            }
            hex::decode_to_slice(&blob.encoded_hex, &mut bytes)
                .map_err(|_| invalid("invalid generation key hex"))?;
            let key = u64::decode_all(&mut bytes.as_slice())
                .map_err(|_| invalid("invalid generation key"))?;
            norito::codec::verify_exact_payload(&key, &bytes)
                .map_err(|_| invalid("noncanonical generation key"))?;
            Ok(key)
        }
        let result = CommitteeStorage::try_restore_admitted(budget.clone(), |current, undo| {
            let mut last = None;
            for original in self.revert {
                let key = key(original.key)?;
                if last.is_some_and(|previous| previous >= key) {
                    return Err(invalid("undo records are not in strict semantic key order"));
                }
                last = Some(key);
                let value = original
                    .value
                    .map(|blob| {
                        RetainedSccpGeneration::decode_snapshot_hex(&blob.encoded_hex, budget)
                    })
                    .transpose()
                    .map_err(|error| match error {
                        GenerationRecordError::Invalid(_) => invalid("invalid undo record"),
                        resource => StateRestoreError::Sccp(
                            sccp_snapshot_state::SccpRestoreError::Generation(resource),
                        ),
                    })?;
                if value.as_ref().is_some_and(|value| value.generation != key) {
                    return Err(invalid("undo record does not match its key"));
                }
                undo(key, value)?;
            }
            last = None;
            for original in self.blocks {
                let key = key(original.key)?;
                if last.is_some_and(|previous| previous >= key) {
                    return Err(invalid(
                        "current records are not in strict semantic key order",
                    ));
                }
                last = Some(key);
                let value = RetainedSccpGeneration::decode_snapshot_hex(
                    &original.value.encoded_hex,
                    budget,
                )
                .map_err(|error| match error {
                    GenerationRecordError::Invalid(_) => invalid("invalid current record"),
                    resource => StateRestoreError::Sccp(
                        sccp_snapshot_state::SccpRestoreError::Generation(resource),
                    ),
                })?;
                if value.generation != key {
                    return Err(invalid("current record does not match its key"));
                }
                current(key, value)?;
            }
            Ok::<_, StateRestoreError>(())
        });
        result.map_err(|error| match error {
            mv::storage::AdmittedBlockError::Admission(error) => error.into(),
            mv::storage::AdmittedBlockError::Callback(error) => error,
        })
    }
}

impl SnapshotStorage {
    /// Restore permanent offence tuples directly into originally admitted current/undo maps.
    pub(super) fn decode_forgery_offences(
        self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<sccp_forgery_custody::OffenceStorage, StateRestoreError> {
        use sccp_forgery_custody::{ForgeryStorageError, OffenceKey, OffenceStorage};
        fn invalid(message: &str) -> StateRestoreError {
            json::Error::InvalidField {
                field: "sccp_forgery_offences".into(),
                message: message.into(),
            }
            .into()
        }
        fn key(
            blob: SnapshotNoritoBlob,
            budget: &iroha_allocation::AllocationBudget,
        ) -> Result<OffenceKey, StateRestoreError> {
            OffenceKey::decode_snapshot_hex(&blob.encoded_hex, budget).map_err(|e| match e {
                ForgeryStorageError::Invalid => invalid("invalid offence tuple"),
                resource => resource.into(),
            })
        }
        fn value(
            blob: SnapshotNoritoBlob,
            budget: &iroha_allocation::AllocationBudget,
        ) -> Result<[u8; 32], StateRestoreError> {
            let text = blob.encoded_hex;
            if !text.len().is_multiple_of(2)
                || text
                    .bytes()
                    .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
            {
                return Err(invalid("noncanonical evidence-id hex"));
            }
            let mut bytes =
                iroha_allocation::ChargedBuffer::new(text.len() / 2, budget).map_err(|e| {
                    StateRestoreError::Evidence(
                        crate::sumeragi::evidence::record::EvidenceRecordRestoreError::Preparation(
                            crate::state::EvidencePreparationError::from(e),
                        ),
                    )
                })?;
            for pair in text.as_bytes().chunks_exact(2) {
                let nibble = |b: u8| {
                    if b.is_ascii_digit() {
                        b - b'0'
                    } else {
                        b - b'a' + 10
                    }
                };
                bytes.push_reserved(nibble(pair[0]) * 16 + nibble(pair[1]));
            }
            let value = <[u8; 32]>::decode_all(&mut bytes.as_slice()).map_err(|e| {
                e.decode_resource_error().map_or_else(
                    || invalid("invalid evidence-id payload"),
                    |e| ForgeryStorageError::Codec(e).into(),
                )
            })?;
            norito::codec::verify_exact_payload(&value, bytes.as_slice()).map_err(|e| {
                e.decode_resource_error().map_or_else(
                    || invalid("noncanonical evidence-id payload"),
                    |e| ForgeryStorageError::Codec(e).into(),
                )
            })?;
            Ok(value)
        }
        let result = OffenceStorage::try_restore_admitted(budget.clone(), |current, undo| {
            let mut last: Option<OffenceKey> = None;
            for row in self.revert {
                let key = key(row.key, budget)?;
                if last.as_ref().is_some_and(|last| last >= &key) {
                    return Err(invalid("undo offence keys are not strictly ordered"));
                }
                last = Some(key.clone());
                undo(key, row.value.map(|blob| value(blob, budget)).transpose()?)?;
            }
            last = None;
            for row in self.blocks {
                let key = key(row.key, budget)?;
                if last.as_ref().is_some_and(|last| last >= &key) {
                    return Err(invalid("current offence keys are not strictly ordered"));
                }
                last = Some(key.clone());
                current(key, value(row.value, budget)?)?;
            }
            Ok::<_, StateRestoreError>(())
        });
        result.map_err(|e| match e {
            mv::storage::AdmittedBlockError::Admission(e) => e.into(),
            mv::storage::AdmittedBlockError::Callback(e) => e,
        })
    }
}

impl SnapshotStorage {
    /// Restore original validator bytes and exact predecessor scalars directly into admitted maps.
    pub(crate) fn decode_light_client_sets(
        self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<crate::smartcontracts::isi::sccp::light_client_set::Storage, StateRestoreError>
    {
        use crate::smartcontracts::isi::sccp::light_client_set::{Key, RetainedSccpLcSet, Storage};
        fn invalid(message: &str) -> StateRestoreError {
            json::Error::InvalidField {
                field: "sccp_light_client_sets".into(),
                message: message.into(),
            }
            .into()
        }
        fn key(blob: SnapshotNoritoBlob) -> Result<Key, StateRestoreError> {
            let text = blob.encoded_hex;
            if text.len() > 128
                || !text.len().is_multiple_of(2)
                || text
                    .bytes()
                    .any(|b| !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(invalid("noncanonical validator key hex"));
            }
            let mut bytes = [0u8; 64];
            let bytes = &mut bytes[..text.len() / 2];
            hex::decode_to_slice(&text, bytes).map_err(|_| invalid("validator key hex"))?;
            let codec = |error: norito::Error| {
                error.decode_resource_error().map_or_else(
                    || invalid("validator key payload"),
                    |original| {
                        StateRestoreError::Sccp(
                            sccp_snapshot_state::SccpRestoreError::ReconciliationDecode(original),
                        )
                    },
                )
            };
            let key = Key::decode_all(&mut &*bytes).map_err(codec)?;
            norito::codec::verify_exact_payload(&key, bytes).map_err(codec)?;
            Ok(key)
        }
        fn value(
            blob: SnapshotNoritoBlob,
            budget: &iroha_allocation::AllocationBudget,
        ) -> Result<RetainedSccpLcSet, StateRestoreError> {
            RetainedSccpLcSet::decode_snapshot_hex(&blob.encoded_hex, budget).map_err(|error| {
                StateRestoreError::Sccp(sccp_snapshot_state::SccpRestoreError::LightClient(error))
            })
        }
        Storage::try_restore_admitted(budget.clone(), |current, undo| {
            let mut last = None;
            for row in self.revert {
                let key = key(row.key)?;
                let value = row.value.map(|blob| value(blob, budget)).transpose()?;
                if last.is_some_and(|last| last >= key)
                    || value.as_ref().is_some_and(|set| set.set_id != key.1)
                {
                    return Err(invalid("unordered or mismatched predecessor validator set"));
                }
                last = Some(key);
                undo(key, value)?;
            }
            last = None;
            for row in self.blocks {
                let key = key(row.key)?;
                let value = value(row.value, budget)?;
                if last.is_some_and(|last| last >= key) || value.set_id != key.1 {
                    return Err(invalid("unordered or mismatched current validator set"));
                }
                last = Some(key);
                current(key, value)?;
            }
            Ok::<(), StateRestoreError>(())
        })
        .map_err(|error| match error {
            mv::storage::AdmittedBlockError::Admission(original) => original.into(),
            mv::storage::AdmittedBlockError::Callback(original) => original,
        })
    }
}
