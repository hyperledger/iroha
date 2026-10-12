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

/// Decode the canonical claim while retaining the original local resource refusal.
fn decode_blob_for_restore<T: DecodeAll + Encode>(
    record: SnapshotNoritoBlob,
    field: &str,
) -> Result<T, StateRestoreError> {
    let invalid = |message| json::Error::InvalidField {
        field: field.to_owned(),
        message,
    };
    let bytes = hex::decode(&record.encoded_hex)
        .map_err(|error| invalid(format!("invalid Norito hex: {error}")))?;
    if hex::encode(&bytes) != record.encoded_hex {
        return Err(invalid("noncanonical Norito hex".into()).into());
    }
    let decoded = T::decode_all(&mut bytes.as_slice()).map_err(|error| {
        StateRestoreError::from(crate::execution_attempt::norito_decode_attempt_error(
            error,
            |error| invalid(format!("invalid Norito record: {error}")),
        ))
    })?;
    if decoded.encode() != bytes {
        return Err(invalid("record is not canonical Norito".into()).into());
    }
    Ok(decoded)
}

impl SnapshotStorage {
    /// Stream validated claims into their original admitted current/undo maps.
    /// Source decoding scratch remains with the enclosing snapshot decoder; only
    /// admitted immutable owners enter the map. No untracked intermediate map exists.
    pub(super) fn decode_admitted<K, D, V, P>(
        self,
        field: &str,
        budget: iroha_allocation::AllocationBudget,
        matches_key: impl Fn(&K, &D) -> bool,
        admit: impl Fn(D) -> Result<V, StateRestoreError>,
    ) -> Result<Storage<K, V, concread::bptree::Prepaid<P>>, StateRestoreError>
    where
        K: mv::Key + Copy + DecodeAll + Encode,
        D: DecodeAll + Encode,
        V: mv::Value,
        P: mv::storage::AdmittedStoragePolicy
            + concread::bptree::ClonePlanning<K, V>
            + concread::bptree::ClonePlanning<K, Option<V>>,
    {
        let invalid = |message: &str| {
            StateRestoreError::from(json::Error::InvalidField {
                field: field.to_owned(),
                message: message.to_owned(),
            })
        };
        Storage::try_restore_admitted(budget, |current, undo| {
            let mut last = None;
            for record in self.revert {
                let key: K = decode_blob_for_restore(record.key, field)?;
                if last.is_some_and(|last| last >= key) {
                    return Err(invalid("undo records are not in strict semantic key order"));
                }
                last = Some(key);
                let value = record
                    .value
                    .map(|blob| {
                        let claim: D = decode_blob_for_restore(blob, field)?;
                        if !matches_key(&key, &claim) {
                            return Err(invalid("undo record does not match its key"));
                        }
                        admit(claim)
                    })
                    .transpose()?;
                undo(key, value)?;
            }
            let mut last = None;
            for record in self.blocks {
                let key: K = decode_blob_for_restore(record.key, field)?;
                if last.is_some_and(|last| last >= key) {
                    return Err(invalid(
                        "current records are not in strict semantic key order",
                    ));
                }
                last = Some(key);
                let claim: D = decode_blob_for_restore(record.value, field)?;
                if !matches_key(&key, &claim) {
                    return Err(invalid("current record does not match its key"));
                }
                current(key, admit(claim)?)?;
            }
            Ok(())
        })
        .map_err(|error| match error {
            mv::storage::AdmittedBlockError::Admission(error) => error.into(),
            mv::storage::AdmittedBlockError::Callback(error) => error,
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
