//! Witness-side proof construction for consensus-authenticated synthetic writes.
use crate::exec_witness::smt::KvPair;
use iroha_crypto::Hash;
use iroha_data_model::block::consensus::ExecWitness;
use iroha_data_model::parliament_casting::{
    PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1, ParliamentTimedOvnCastingWitnessProofV1,
};
use iroha_data_model::validation_fee::{
    VALIDATION_FEE_POLICY_WITNESS_KEY_V1, ValidationFeePolicyWitnessProofV1,
};
use std::collections::{BTreeMap, BTreeSet};

/// Caller-supplied bounds for constructing one local FASTPQ source opening or archive.
#[derive(Debug, Clone, Copy)]
pub struct FastpqSourceOpeningBuildLimits {
    /// Maximum ordinary writes inspected before cloning any witness key or value.
    pub max_ordinary_writes: usize,
    /// Maximum aggregate raw key/value bytes across those ordinary writes.
    pub max_ordinary_write_bytes: usize,
    /// Maximum complete executed-entry count.
    pub max_executed_entries: u32,
    /// Maximum complete nonempty execution-entry transfer-bundle statements.
    pub max_statements: u32,
    /// Manifest decoding budget, preserving any stricter enclosing Norito scope.
    pub manifest_decode: norito::DecodeLimits,
}

#[cfg(test)]
/// Complete local source archive with one shared ordinary-write path.
///
/// The leaves remain borrowed from the caller's exact archive. Neither this local
/// result nor its computed root authenticates execution ownership or finality.
pub(crate) struct FastpqOrdinarySourceArchive<'leaves> {
    /// Canonical manifest matching every supplied leaf and the fixed witness write.
    pub(crate) manifest: iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1,
    /// Complete validated leaf sequence, without an additional owned copy.
    pub(crate) leaves: &'leaves [iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1],
    /// Exactly 256 siblings for the one fixed D7 ordinary-write key.
    pub(crate) manifest_siblings: Vec<Hash>,
    /// Computed ordinary-write root, requiring independent finality authentication.
    pub(crate) ordinary_root: Hash,
}

#[cfg(test)]
/// Bounded manifest and complete-leaf validation before ordinary tree allocation.
///
/// Separating preparation from [`Self::build`] lets a leaf-opening caller reject
/// absent positions before cloning ordinary writes, preserving its existing order.
pub(crate) struct PreparedFastpqOrdinarySourceArchive<'witness, 'leaves> {
    witness: &'witness ExecWitness,
    target: &'witness iroha_data_model::block::consensus::ExecKv,
    manifest: iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1,
    leaves: &'leaves [iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1],
    limits: FastpqSourceOpeningBuildLimits,
}

#[cfg(test)]
/// Validate the exact fixed manifest and complete borrowed source leaf archive.
///
/// The caller must supply the independently obtained complete execution-entry inventory,
/// including entries without transfers. It is never reconstructed from the leaves or the
/// advertised manifest count. Preparation binds every entry and every leaf to that inventory.
/// This accepts a canonical empty manifest without inventing a leaf opening.
/// Counts and raw ordinary-write bytes are bounded before cloning any key/value.
/// The returned preparation does not establish execution ownership or finality.
///
/// # Errors
/// Rejects exceeded bounds, malformed or duplicate reserved keys, noncanonical
/// manifests, and inconsistent source context, complete leaf order or counts.
pub(crate) fn prepare_fastpq_ordinary_source_archive_v1<'witness, 'leaves>(
    witness: &'witness ExecWitness,
    source: iroha_data_model::fastpq::FastpqSourceStatementContextV1,
    expected_entries: &[iroha_data_model::fastpq::FastpqSourceExecutionEntryV1],
    leaves: &'leaves [iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1],
    limits: FastpqSourceOpeningBuildLimits,
) -> Result<PreparedFastpqOrdinarySourceArchive<'witness, 'leaves>, String> {
    use iroha_data_model::{
        execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
        fastpq::{
            FASTPQ_SOURCE_STATEMENT_MANIFEST_MAX_BYTES_V1, FastpqOrdinarySourceStatementManifestV1,
            build_fastpq_ordinary_source_statement_manifest_v1,
        },
    };
    if !u32::try_from(expected_entries.len())
        .is_ok_and(|count| count <= limits.max_executed_entries)
        || witness.writes.len() > limits.max_ordinary_writes
        || !u32::try_from(leaves.len()).is_ok_and(|count| count <= limits.max_statements)
    {
        return Err("FASTPQ source opening exceeds its write or entry count cap".to_owned());
    }
    let mut total_bytes = 0_usize;
    let mut manifest_write = None;
    for write in &witness.writes {
        total_bytes = total_bytes
            .checked_add(write.key.len())
            .and_then(|total| total.checked_add(write.value.len()))
            .filter(|total| *total <= limits.max_ordinary_write_bytes)
            .ok_or_else(|| {
                "FASTPQ source opening exceeds its ordinary-write byte cap".to_owned()
            })?;
        if write.key.first() == FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1.first() {
            if write.key != FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1
                || manifest_write.is_some()
            {
                return Err(
                    "FASTPQ source witness contains a malformed or duplicate reserved key"
                        .to_owned(),
                );
            }
            manifest_write = Some(write);
        }
    }
    let target =
        manifest_write.ok_or_else(|| "FASTPQ source manifest write is absent".to_owned())?;
    if target.value.len() > FASTPQ_SOURCE_STATEMENT_MANIFEST_MAX_BYTES_V1 {
        return Err("FASTPQ source manifest exceeds its canonical frame cap".to_owned());
    }
    let manifest: FastpqOrdinarySourceStatementManifestV1 =
        norito::decode_canonical_with_limits(&target.value, limits.manifest_decode).map_err(
            |error| format!("FASTPQ source manifest is not bounded canonical Norito: {error}"),
        )?;
    let rebuilt = build_fastpq_ordinary_source_statement_manifest_v1(
        source,
        expected_entries,
        leaves,
        limits.max_executed_entries,
        limits.max_statements,
    )
    .ok_or_else(|| "FASTPQ source leaf archive has invalid context, order or count".to_owned())?;
    if manifest != rebuilt {
        return Err("FASTPQ source manifest differs from its complete leaf archive".to_owned());
    }
    Ok(PreparedFastpqOrdinarySourceArchive {
        witness,
        target,
        manifest,
        leaves,
        limits,
    })
}

#[cfg(test)]
impl<'leaves> PreparedFastpqOrdinarySourceArchive<'_, 'leaves> {
    /// Construct the one shared ordinary-write path from the bounded witness.
    ///
    /// Other keys retain the ordinary tree's existing last-write-wins projection.
    /// Empty source archives still prove the actual manifest write. The returned
    /// leaves borrow only the original archive, so the witness can be released.
    ///
    /// # Errors
    /// Rejects a sparse-tree construction failure or a path that does not
    /// reconstruct the manifest under the computed ordinary-write root.
    pub(crate) fn build(self) -> Result<FastpqOrdinarySourceArchive<'leaves>, String> {
        use iroha_data_model::fastpq::verify_fastpq_ordinary_source_statement_manifest_write_v1;

        let canonical = self
            .witness
            .writes
            .iter()
            .map(|write| (write.key.clone(), write.value.clone()))
            .collect::<BTreeMap<_, _>>();
        let ordinary = canonical
            .into_iter()
            .map(|(key, value)| KvPair::new(key, value))
            .collect::<Vec<_>>();
        let ordinary_root = crate::exec_witness::smt::compute_post_state_root(&[], &ordinary);
        let target = KvPair::new(self.target.key.clone(), self.target.value.clone());
        let manifest_siblings = sparse_smt_siblings(&ordinary, &target)?;
        if !verify_fastpq_ordinary_source_statement_manifest_write_v1(
            &self.manifest,
            self.manifest.source,
            &manifest_siblings,
            ordinary_root,
            self.limits.max_executed_entries,
            self.limits.max_statements,
        ) {
            return Err(
                "constructed FASTPQ source opening does not reconstruct the ordinary-write root"
                    .to_owned(),
            );
        }
        Ok(FastpqOrdinarySourceArchive {
            manifest: self.manifest,
            leaves: self.leaves,
            manifest_siblings,
            ordinary_root,
        })
    }
}

#[cfg(test)]
/// Construct a bounded complete transport archive with one shared manifest path.
///
/// The existing preparation validates raw write/count/byte limits, the canonical
/// D7 manifest and every supplied leaf before ordinary witness keys/values are
/// copied. One shared archive build derives and checks its ordinary-write path;
/// it is not repeated for individual leaves. The caller's already-owned leaf
/// allocation is moved into the payload without a second copy, including when
/// the leaf sequence is empty. The witness is only borrowed and is not retained.
///
/// The caller supplies the complete independently obtained execution-entry inventory,
/// including entries with no transfer leaves. It is checked against the manifest's
/// source-entry commitment and every leaf before the witness tree is allocated.
/// The payload and returned computed ordinary-write root establish consistency
/// with the supplied witness/source/entries only. They do not authenticate finality,
/// validator-owned execution completeness, durable retention or spend authority.
/// These construction limits do not select a production profile or bound encoded
/// transport bytes; callers must separately bound canonical encoding/decoding.
/// TODO: integrate the durable source owner and independently authenticated
/// finality admission after the D7 policy and execution-accounting gates are met.
///
/// # Errors
/// Rejects every preparation/build error unchanged, or a manifest path whose
/// depth cannot be represented by the transport's exact 256-sibling array.
pub fn fastpq_ordinary_source_statement_archive_v1(
    witness: &ExecWitness,
    source: iroha_data_model::fastpq::FastpqSourceStatementContextV1,
    expected_entries: &[iroha_data_model::fastpq::FastpqSourceExecutionEntryV1],
    leaves: Vec<iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1>,
    limits: FastpqSourceOpeningBuildLimits,
) -> Result<
    (
        iroha_data_model::fastpq::FastpqOrdinarySourceStatementArchiveV1,
        Hash,
    ),
    String,
> {
    use iroha_data_model::fastpq::{
        FASTPQ_ORDINARY_SOURCE_STATEMENT_ARCHIVE_VERSION_V1, FastpqOrdinarySourceStatementArchiveV1,
    };

    let (manifest, manifest_siblings, ordinary_root) = {
        let archive = prepare_fastpq_ordinary_source_archive_v1(
            witness,
            source,
            expected_entries,
            &leaves,
            limits,
        )?
        .build()?;
        (
            archive.manifest,
            archive.manifest_siblings,
            archive.ordinary_root,
        )
    };
    let manifest_siblings = manifest_siblings.try_into().map_err(|_| {
        "FASTPQ source archive manifest path does not have exactly 256 siblings".to_owned()
    })?;
    Ok((
        FastpqOrdinarySourceStatementArchiveV1 {
            version: FASTPQ_ORDINARY_SOURCE_STATEMENT_ARCHIVE_VERSION_V1,
            manifest,
            leaves,
            manifest_siblings,
        },
        ordinary_root,
    ))
}

#[cfg(test)]
/// Construct one bounded opening from an exact local witness and complete leaf archive.
///
/// The reserved FASTPQ key family must contain exactly one canonical fixed-key
/// manifest. Its source-entry commitment must match the caller's independently obtained
/// complete inventory, including entries without transfers, and its root/count must match
/// every supplied ordered leaf before an opening is returned. Other ordinary writes use
/// the existing consensus last-write-wins projection and sparse-tree proof constructor.
///
/// Both the returned opening and computed root remain untrusted. This function
/// neither authenticates the witness nor attests that its manifest was derived by
/// validator execution. A consumer still needs independently authenticated finality.
///
/// # Errors
/// Rejects exceeded bounds, malformed/duplicate reserved keys, noncanonical
/// manifests, inconsistent source/leaf archives, absent positions and proof errors.
pub fn fastpq_ordinary_source_statement_opening_v1(
    witness: &ExecWitness,
    source: iroha_data_model::fastpq::FastpqSourceStatementContextV1,
    expected_entries: &[iroha_data_model::fastpq::FastpqSourceExecutionEntryV1],
    leaves: &[iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1],
    statement_index: u32,
    limits: FastpqSourceOpeningBuildLimits,
) -> Result<
    (
        iroha_data_model::fastpq::FastpqOrdinarySourceStatementOpeningV1,
        Hash,
    ),
    String,
> {
    use iroha_crypto::MerkleTree;
    use iroha_data_model::fastpq::{
        FastpqOrdinarySourceStatementOpeningV1, fastpq_ordinary_source_statement_leaf_hash_v1,
        verify_fastpq_ordinary_source_statement_membership_v1,
    };
    let prepared = prepare_fastpq_ordinary_source_archive_v1(
        witness,
        source,
        expected_entries,
        leaves,
        limits,
    )?;
    let leaf_index = usize::try_from(statement_index)
        .map_err(|_| "FASTPQ source statement index is not representable".to_owned())?;
    prepared
        .leaves
        .get(leaf_index)
        .ok_or_else(|| "FASTPQ source statement index is absent".to_owned())?;
    let hashes = leaves
        .iter()
        .map(|leaf| {
            fastpq_ordinary_source_statement_leaf_hash_v1(leaf)
                .ok_or_else(|| "FASTPQ source leaf exceeds its canonical encoding bound".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tree: MerkleTree<_> = hashes.into_iter().collect();
    let membership = tree
        .get_proof(statement_index)
        .ok_or_else(|| "FASTPQ source statement membership is absent".to_owned())?;
    let archive = prepared.build()?;
    let leaf = archive.leaves[leaf_index];
    let opening = FastpqOrdinarySourceStatementOpeningV1 {
        manifest: archive.manifest,
        leaf,
        membership,
        manifest_siblings: archive.manifest_siblings,
    };
    // The common archive builder already verified the manifest's ordinary-write
    // inclusion. Keep the per-leaf membership check without hashing that path twice.
    if !verify_fastpq_ordinary_source_statement_membership_v1(
        &opening.leaf,
        &leaf,
        &opening.manifest,
        &opening.membership,
        limits.max_executed_entries,
        limits.max_statements,
    ) {
        return Err(
            "constructed FASTPQ source opening does not reconstruct the ordinary-write root"
                .to_owned(),
        );
    }
    Ok((opening, archive.ordinary_root))
}

/// Construct the exact fixed-key validation-fee policy proof against the ordinary-write SMT.
pub(crate) fn validation_fee_policy_witness_proof_v1(
    witness: &ExecWitness,
) -> Result<(ValidationFeePolicyWitnessProofV1, Hash), String> {
    let target_count = witness
        .writes
        .iter()
        .filter(|entry| entry.key.as_slice() == VALIDATION_FEE_POLICY_WITNESS_KEY_V1)
        .count();
    if target_count != 1 {
        return Err(format!(
            "execution witness contains {target_count} validation-fee synthetic writes; expected exactly one"
        ));
    }
    let mut canonical = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for entry in &witness.writes {
        canonical.insert(entry.key.clone(), entry.value.clone());
    }
    let ordinary = canonical
        .into_iter()
        .map(|(key, value)| KvPair::new(key, value))
        .collect::<Vec<_>>();
    let ordinary_root = crate::exec_witness::smt::compute_post_state_root(&[], &ordinary);
    let target = ordinary
        .iter()
        .find(|pair| pair.key.as_slice() == VALIDATION_FEE_POLICY_WITNESS_KEY_V1)
        .ok_or_else(|| {
            "validation-fee synthetic write is absent from ordinary writes".to_owned()
        })?;
    let siblings = sparse_smt_siblings(&ordinary, target)?;
    let proof = ValidationFeePolicyWitnessProofV1 {
        key: target.key.clone(),
        value: target.value.clone(),
        siblings,
    };
    if !proof.verify(ordinary_root) {
        return Err(
            "constructed validation-fee witness proof does not reconstruct the ordinary-write root"
                .to_owned(),
        );
    }
    Ok((proof, ordinary_root))
}
/// Construct the exact fixed-key Parliament timed-OVN casting proof against the ordinary-write SMT.
pub(crate) fn parliament_timed_ovn_casting_witness_proof_v1(
    witness: &ExecWitness,
) -> Result<(ParliamentTimedOvnCastingWitnessProofV1, Hash), String> {
    let target_count = witness
        .writes
        .iter()
        .filter(|entry| entry.key.as_slice() == PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1)
        .count();
    if target_count != 1 {
        return Err(format!(
            "execution witness contains {target_count} Parliament timed-OVN casting synthetic writes; expected exactly one"
        ));
    }
    let mut canonical = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for entry in &witness.writes {
        canonical.insert(entry.key.clone(), entry.value.clone());
    }
    let ordinary = canonical
        .into_iter()
        .map(|(key, value)| KvPair::new(key, value))
        .collect::<Vec<_>>();
    let ordinary_root = crate::exec_witness::smt::compute_post_state_root(&[], &ordinary);
    let target = ordinary
        .iter()
        .find(|pair| pair.key.as_slice() == PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1)
        .ok_or_else(|| {
            "Parliament timed-OVN casting synthetic write is absent from ordinary writes".to_owned()
        })?;
    let siblings = sparse_smt_siblings(&ordinary, target)?;
    let proof = ParliamentTimedOvnCastingWitnessProofV1 {
        key: target.key.clone(),
        value: target.value.clone(),
        siblings,
    };
    if !proof.verify(ordinary_root) {
        return Err(
            "constructed Parliament timed-OVN casting witness proof does not reconstruct the ordinary-write root"
                .to_owned(),
        );
    }
    Ok((proof, ordinary_root))
}
/// Retain the complete native fee corpus and its fixed root/count inclusion proof.
pub(crate) fn fee_evidence_block_proof_v1(
    witness: &ExecWitness,
) -> Result<
    (
        iroha_data_model::fee_evidence::FeeEvidenceBlockProofV1,
        Hash,
    ),
    String,
> {
    use iroha_data_model::{
        execution_witness::{FEE_EVIDENCE_RECORD_TAG_V1, FEE_EVIDENCE_WITNESS_KEY_V1},
        fee_evidence::{FeeEvidenceBlockProofV1, FeeEvidenceRecordV1, FeeEvidenceWitnessProofV1},
    };
    let mut ordinary = BTreeMap::new();
    let mut records = Vec::new();
    for entry in &witness.writes {
        if ordinary
            .insert(entry.key.clone(), entry.value.clone())
            .is_some()
        {
            return Err("duplicate ordinary witness key in native fee evidence".into());
        }
        if entry.key.first() == Some(&FEE_EVIDENCE_RECORD_TAG_V1) {
            let record: FeeEvidenceRecordV1 = norito::decode_canonical(&entry.value)
                .map_err(|e| format!("noncanonical native fee record: {e}"))?;
            let mut expected_key = vec![FEE_EVIDENCE_RECORD_TAG_V1];
            expected_key.extend_from_slice(Hash::new(record.key.as_ref().as_bytes()).as_ref());
            if entry.key != expected_key {
                return Err("native fee witness key does not bind its record".into());
            }
            records.push(record);
        }
    }
    records.sort_by(|a, b| a.key.cmp(&b.key));
    let ordinary = ordinary
        .into_iter()
        .map(|(key, value)| KvPair::new(key, value))
        .collect::<Vec<_>>();
    let target = ordinary
        .iter()
        .find(|entry| entry.key.as_slice() == FEE_EVIDENCE_WITNESS_KEY_V1)
        .ok_or_else(|| "native fee evidence root/count write is absent".to_owned())?;
    let root = crate::exec_witness::smt::compute_post_state_root(&[], &ordinary);
    let proof = FeeEvidenceBlockProofV1 {
        snapshot_witness: FeeEvidenceWitnessProofV1 {
            key: target.key.clone(),
            value: target.value.clone(),
            siblings: sparse_smt_siblings(&ordinary, target)?,
        },
        records,
    };
    if !proof.verify(root) {
        return Err("native fee corpus differs from the authenticated root/count".into());
    }
    if norito::to_bytes(&proof).map_err(|e| e.to_string())?.len()
        > iroha_data_model::fee_evidence::MAX_FEE_EVIDENCE_BLOCK_BYTES_V1
    {
        return Err("native fee corpus exceeds the bounded durable byte budget".into());
    }
    Ok((proof, root))
}

/// Build a fixed-depth ordinary-write proof for an already selected exact key/value.
pub(crate) fn sparse_smt_siblings(inputs: &[KvPair], target: &KvPair) -> Result<Vec<Hash>, String> {
    let empty = Hash::new([]);
    let target_path = hash_bytes(&target.key).to_vec();
    let mut raw_paths = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut current = BTreeMap::<Vec<u8>, Hash>::new();
    for pair in inputs {
        let path = hash_bytes(&pair.key).to_vec();
        if let Some(existing_key) = raw_paths.insert(path.clone(), pair.key.clone())
            && existing_key != pair.key
        {
            return Err("ordinary-write SMT contains a key-path hash collision".to_owned());
        }
        current.insert(path, leaf_hash(pair));
    }
    if !current.contains_key(&target_path) {
        return Err("active-receiver target path is absent from ordinary writes".to_owned());
    }
    let mut current_target = target_path;
    let mut siblings = Vec::with_capacity(256);
    let mut current_bits = 256_u16;
    while current_bits > 0 {
        let sibling = sibling_prefix(&current_target, current_bits);
        siblings.push(current.get(&sibling).copied().unwrap_or(empty));
        let mut parents = BTreeSet::new();
        for prefix in current.keys() {
            parents.insert(parent_prefix(prefix, current_bits));
        }
        let mut next = BTreeMap::new();
        for parent in parents {
            let left = child_prefix(&parent, current_bits, false);
            let right = child_prefix(&parent, current_bits, true);
            next.insert(
                parent,
                node_hash(
                    current.get(&left).copied().unwrap_or(empty),
                    current.get(&right).copied().unwrap_or(empty),
                ),
            );
        }
        current_target = parent_prefix(&current_target, current_bits);
        current = next;
        current_bits -= 1;
    }
    if siblings.len() != 256 {
        return Err("ordinary-write SMT proof has the wrong depth".to_owned());
    }
    Ok(siblings)
}
fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    Hash::new(bytes).into()
}
fn leaf_hash(pair: &KvPair) -> Hash {
    let mut preimage = Vec::with_capacity(1 + 2 * Hash::LENGTH);
    preimage.push(0);
    preimage.extend_from_slice(&hash_bytes(&pair.key));
    preimage.extend_from_slice(&hash_bytes(&pair.value));
    Hash::new(preimage)
}
fn node_hash(left: Hash, right: Hash) -> Hash {
    let mut preimage = Vec::with_capacity(1 + 2 * Hash::LENGTH);
    preimage.push(1);
    preimage.extend_from_slice(left.as_ref());
    preimage.extend_from_slice(right.as_ref());
    Hash::new(preimage)
}
fn parent_prefix(prefix: &[u8], len_bits: u16) -> Vec<u8> {
    truncate_prefix(prefix, len_bits - 1)
}
fn sibling_prefix(prefix: &[u8], len_bits: u16) -> Vec<u8> {
    let parent = parent_prefix(prefix, len_bits);
    let bit_index = len_bits - 1;
    let byte_index = usize::from(bit_index / 8);
    let bit_offset = (bit_index % 8) as u8;
    let right = prefix
        .get(byte_index)
        .is_some_and(|byte| byte & (1_u8 << bit_offset) != 0);
    child_prefix(&parent, len_bits, !right)
}
fn child_prefix(parent: &[u8], child_len_bits: u16, right: bool) -> Vec<u8> {
    let mut output = parent.to_vec();
    let bit_index = child_len_bits - 1;
    let byte_index = usize::from(bit_index / 8);
    let bit_offset = (bit_index % 8) as u8;
    if output.len() <= byte_index {
        output.resize(byte_index + 1, 0);
    }
    let mask = 1_u8 << bit_offset;
    if right {
        output[byte_index] |= mask;
    } else {
        output[byte_index] &= !mask;
    }
    mask_tail_bits(&mut output, child_len_bits);
    output
}
fn truncate_prefix(prefix: &[u8], len_bits: u16) -> Vec<u8> {
    if len_bits == 0 {
        return Vec::new();
    }
    let byte_len = usize::from(len_bits.div_ceil(8));
    let mut output = prefix[..prefix.len().min(byte_len)].to_vec();
    output.resize(byte_len, 0);
    mask_tail_bits(&mut output, len_bits);
    output
}
fn mask_tail_bits(bytes: &mut [u8], len_bits: u16) {
    let remainder = (len_bits % 8) as u8;
    if remainder == 0 || bytes.is_empty() {
        return;
    }
    let mask = (1_u16 << remainder) as u8 - 1;
    if let Some(last) = bytes.last_mut() {
        *last &= mask;
    }
}
#[cfg(test)]
#[path = "receiver_snapshot/fastpq_source_archive_tests.rs"]
mod fastpq_source_archive_tests;

#[cfg(test)]
#[path = "receiver_snapshot/fastpq_source_archive_bridge_tests.rs"]
mod fastpq_source_archive_bridge_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::block::consensus::ExecKv;
    use iroha_data_model::parliament_casting::ParliamentTimedOvnCastingSnapshotCommitmentV1;
    #[test]
    fn parliament_casting_fixed_write_has_256_siblings_and_rejects_tampering() {
        let snapshot = ParliamentTimedOvnCastingSnapshotCommitmentV1::empty(7);
        let witness = ExecWitness {
            reads: Vec::new(),
            writes: vec![
                ExecKv {
                    key: b"ordinary-a".to_vec(),
                    value: b"one".to_vec(),
                },
                ExecKv {
                    key: PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1.to_vec(),
                    value: norito::to_bytes(&snapshot).expect("encode casting snapshot"),
                },
                ExecKv {
                    key: b"ordinary-b".to_vec(),
                    value: b"two".to_vec(),
                },
            ],
            fastpq_transcripts: Vec::new(),
            fastpq_batches: Vec::new(),
        };
        let (proof, root) =
            parliament_timed_ovn_casting_witness_proof_v1(&witness).expect("casting proof");
        assert_eq!(proof.siblings.len(), 256);
        assert_eq!(proof.commitment().expect("snapshot commitment"), snapshot);
        assert!(proof.verify(root));

        let mut tampered = proof.clone();
        tampered.siblings[127] = Hash::new(b"tampered casting sibling");
        assert!(!tampered.verify(root));
        let mut wrong_value = proof;
        wrong_value.value.push(0);
        assert!(!wrong_value.verify(root));
    }

    #[test]
    fn parliament_casting_fixed_write_must_appear_exactly_once() {
        let empty = ExecWitness {
            reads: Vec::new(),
            writes: Vec::new(),
            fastpq_transcripts: Vec::new(),
            fastpq_batches: Vec::new(),
        };
        assert!(parliament_timed_ovn_casting_witness_proof_v1(&empty).is_err());

        let snapshot = ParliamentTimedOvnCastingSnapshotCommitmentV1::empty(7);
        let value = norito::to_bytes(&snapshot).expect("encode casting snapshot");
        let duplicate = ExecWitness {
            reads: Vec::new(),
            writes: vec![
                ExecKv {
                    key: PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1.to_vec(),
                    value: value.clone(),
                },
                ExecKv {
                    key: PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1.to_vec(),
                    value,
                },
            ],
            fastpq_transcripts: Vec::new(),
            fastpq_batches: Vec::new(),
        };
        assert!(parliament_timed_ovn_casting_witness_proof_v1(&duplicate).is_err());
    }

    #[test]
    fn captured_block_synthetic_write_families_share_one_authenticated_root() {
        use crate::exec_witness as recorder;
        use iroha_data_model::{asset::AssetId, execution_witness::ExecutionWitnessKeyTagV1};
        use mv::storage::StorageReadOnly;
        crate::state::native_capture_fixture::with_native_capture_source(
            true,
            |state, mut state_block, _recording, mut source, source_hash| {
                let header = source.header();
                let tx_set_hash: [u8; 32] =
                    iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
                        source.external_entrypoints_slice().iter(),
                    )
                    .unwrap()
                    .into();
                crate::state::native_capture_fixture::seal_native_source(
                    &mut state_block,
                    &mut source,
                )
                .unwrap();
                // This root-composition control deliberately retains the one ordinary
                // balance leaf from the original test. Its bytes now come from the
                // genuine completed transfer and its actual applied World overlay;
                // the producer's quantity provenance remains owned by the D7 seal.
                assert_eq!(source.fastpq_transcripts().len(), 1);
                let transcripts = &source.fastpq_transcripts()[&source_hash];
                assert_eq!(transcripts.len(), 1);
                assert_eq!(transcripts[0].deltas.len(), 1);
                let delta = &transcripts[0].deltas[0];
                let asset = AssetId::of(delta.asset_definition.clone(), delta.from_account.clone());
                let post = state_block
                    .world
                    .assets
                    .get(&asset)
                    .expect("the genuine transfer retains its source balance")
                    .as_ref();
                assert_eq!(post, &delta.from_balance_after);
                recorder::record_write_asset(&asset, post);
                let mut ordinary_key = vec![ExecutionWitnessKeyTagV1::AssetBalance as u8];
                ordinary_key.extend_from_slice(asset.to_string().as_bytes());
                let ordinary_value = iroha_primitives::json::Json::new(post.clone())
                    .get()
                    .as_bytes()
                    .to_vec();
                assert_eq!(
                    state_block
                        .fastpq_source_inventory()
                        .unwrap()
                        .unwrap()
                        .tx_set_hash(),
                    tx_set_hash
                );
                state_block.capture_exec_witness().unwrap();
                let witness = state_block
                    .take_exec_witness()
                    .expect("actual captured witness");
                let encoded = norito::encode_canonical(witness.wire()).expect("encode witness");
                let decoded: ExecWitness =
                    norito::decode_canonical(&encoded).expect("decode witness");
                assert_eq!(&decoded, witness.wire());
                assert_eq!(witness.writes.len(), 6);
                assert_eq!(witness.fastpq_transcripts.len(), 1);
                let mut ordinary = witness
                    .writes
                    .iter()
                    .filter(|write| write.key == ordinary_key);
                assert_eq!(
                    ordinary
                        .next()
                        .expect("the ordinary balance leaf is retained")
                        .value,
                    ordinary_value,
                );
                assert!(ordinary.next().is_none());
                // All four fixed native contexts and the ordinary source manifest
                // remain authenticated alongside this genuine transfer's writes.
                for key in [
                        iroha_data_model::execution_witness::VALIDATION_FEE_POLICY_WITNESS_KEY_V1,
                        iroha_data_model::execution_witness::PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1,
                        iroha_data_model::sumeragi_finality::SUMERAGI_LANE_STATE_WITNESS_KEY,
                        iroha_data_model::execution_witness::FEE_EVIDENCE_WITNESS_KEY_V1,
                    ] {
                        assert_eq!(
                            witness.writes.iter().filter(|write| write.key == key).count(),
                            1,
                            "the complete native context appears exactly once",
                        );
                    }
                assert_eq!(witness.writes.iter().filter(|write| write.key.as_slice() ==
                iroha_data_model::execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1).count(), 1);
                let native_lanes =
                    iroha_data_model::sumeragi_finality::NativeLaneStateProof::from_witness(
                        &decoded,
                        &iroha_allocation::AllocationBudget::new(64 * 1024),
                    )
                    .expect("actual complete native lane state proof");
                let (fee, fee_root) =
                    validation_fee_policy_witness_proof_v1(&decoded).expect("actual fee proof");
                let (casting, casting_root) =
                    parliament_timed_ovn_casting_witness_proof_v1(&decoded)
                        .expect("actual casting proof");
                let (fee_evidence, fee_evidence_root) =
                    fee_evidence_block_proof_v1(&decoded).expect("complete captured fee evidence");
                assert_eq!(fee_root, casting_root);
                assert_eq!(fee_root, fee_evidence_root);
                assert!(fee_evidence.verify(fee_root));
                assert!(fee_evidence.records.is_empty());
                let fee_snapshot = fee_evidence.snapshot_witness.commitment().unwrap();
                assert_eq!(fee_snapshot.evaluated_height, header.height().get());
                assert_eq!(fee_snapshot.count, 0);
                let mut omitted_fee = decoded.clone();
                omitted_fee.writes.retain(|write| {
                    write.key != iroha_data_model::execution_witness::FEE_EVIDENCE_WITNESS_KEY_V1
                });
                assert!(fee_evidence_block_proof_v1(&omitted_fee).is_err());
                assert!(native_lanes.verify(
                    *state.network_id_ref(),
                    header.height().get(),
                    fee_root
                ));
                assert!(fee.verify(fee_root));
                assert!(casting.verify(fee_root));
            },
        );
    }
}

#[cfg(test)]
mod native_fee_evidence_tests {
    use super::*;
    use iroha_data_model::{block::consensus::ExecKv, execution_witness::*, fee_evidence::*};
    #[test]
    fn native_fee_complete_corpus_and_compact_membership_detect_tampering() {
        let account_id = iroha_data_model::account::AccountId::new(
            iroha_crypto::KeyPair::from_seed(vec![27; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let mut record = FeeEvidenceRecordV1 {
            key: "retail_fee_receipts_v1/test".parse().unwrap(),
            recorded_at_height: 19,
            payload: FeeEvidencePayloadV1::RetailReceipt(
                iroha_data_model::validation_fee::RetailFeeReceiptV1 {
                    wallet_id: account_id.clone(),
                    sequence: 1,
                    previous_receipt_hash: None,
                    receipt_id: [27; 32],
                    account_id,
                    kind: iroha_data_model::validation_fee::RetailFeeReceiptKindV1::Maintenance,
                    billing_month_start_ms: 1_793_430_000_000,
                    policy_revision: 1,
                    policy_hash: [23; 32],
                    scheduled_minor: 100,
                    collected_minor: 30,
                    waived_minor: 70,
                    payment_count: 0,
                    source_transaction_hash: None,
                    effective_at_ms: Some(1_796_022_000_000),
                    recorded_at_height: 19,
                    assessment: None,
                },
            ),
        };
        if let FeeEvidencePayloadV1::RetailReceipt(r) = &record.payload {
            record.key =
                iroha_data_model::validation_fee::retail_fee_receipt_state_key_v1(r).unwrap();
        }
        let snapshot = FeeEvidenceSnapshotV1::from_records(19, &[record.clone()]).unwrap();
        let mut record_key = vec![FEE_EVIDENCE_RECORD_TAG_V1];
        record_key.extend_from_slice(Hash::new(record.key.as_ref().as_bytes()).as_ref());
        let witness = ExecWitness {
            writes: vec![
                ExecKv {
                    key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
                    value: norito::to_bytes(&snapshot).unwrap(),
                },
                ExecKv {
                    key: record_key,
                    value: norito::to_bytes(&record).unwrap(),
                },
                ExecKv {
                    key: b"ordinary-user-write".to_vec(),
                    value: vec![9],
                },
            ],
            ..ExecWitness::default()
        };
        let (proof, root) = fee_evidence_block_proof_v1(&witness).unwrap();
        assert!(proof.verify(root));
        let compact = proof.record_proof(&record.key).unwrap();
        assert!(compact.verify(root));
        let decoded =
            norito::decode_canonical::<FeeEvidenceBlockProofV1>(&norito::to_bytes(&proof).unwrap())
                .unwrap();
        assert_eq!(decoded, proof);
        let mut omitted = proof.clone();
        omitted.records.clear();
        assert!(!omitted.verify(root));
        let mut corrupt = compact.clone();
        corrupt.record.recorded_at_height += 1;
        assert!(!corrupt.verify(root));
        let mut corrupt = compact;
        corrupt.snapshot_witness.siblings[0] = Hash::new(b"wrong");
        assert!(!corrupt.verify(root));
        assert!(!proof.verify(Hash::new(b"other-block")));
        let mut omitted = witness.clone();
        omitted.writes.remove(1);
        assert!(fee_evidence_block_proof_v1(&omitted).is_err());
        let mut duplicate = witness.clone();
        duplicate.writes.push(duplicate.writes[0].clone());
        assert!(fee_evidence_block_proof_v1(&duplicate).is_err());
        let mut wrong_key = witness;
        wrong_key.writes[1].key[1] ^= 1;
        assert!(fee_evidence_block_proof_v1(&wrong_key).is_err());
    }
    #[test]
    fn native_fee_empty_block_still_requires_an_authenticated_zero_count() {
        let snapshot = FeeEvidenceSnapshotV1::from_records(19, &[]).unwrap();
        let witness = ExecWitness {
            writes: vec![ExecKv {
                key: FEE_EVIDENCE_WITNESS_KEY_V1.to_vec(),
                value: norito::to_bytes(&snapshot).unwrap(),
            }],
            ..ExecWitness::default()
        };
        let (proof, root) = fee_evidence_block_proof_v1(&witness).unwrap();
        assert!(proof.verify(root));
        assert!(fee_evidence_block_proof_v1(&ExecWitness::default()).is_err());
    }
}
