use super::*;
use blake3::{Hasher, hash as blake3_hash};
use iroha_crypto::Hash;
use iroha_data_model::{
    content::{ContentBundleManifest, ContentCachePolicy},
    da::types::{BlobClass, RetentionPolicy},
};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::codec::Encode;
use std::{collections::BTreeMap, str};
impl Execute for iroha_data_model::isi::content::PublishContentBundle {
    #[allow(clippy::too_many_lines)]
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let config = &state_transaction.content;
        if !config.publish_allow_accounts.is_empty()
            && !config
                .publish_allow_accounts
                .iter()
                .any(|id| id == authority)
        {
            return Err(Error::InvariantViolation(
                "content publishing not permitted for this account".into(),
            ));
        }
        let tar_len = self.tarball.len() as u64;
        if tar_len == 0 {
            return Err(Error::InvariantViolation(
                "content tarball must not be empty".into(),
            ));
        }
        if tar_len > config.max_bundle_bytes {
            return Err(Error::InvariantViolation(
                format!(
                    "content tarball exceeds max size ({} > {})",
                    tar_len, config.max_bundle_bytes
                )
                .into(),
            ));
        }
        let bundle_id = Hash::new(&self.tarball);
        if bundle_id != self.bundle_id {
            return Err(Error::InvariantViolation(
                "bundle_id does not match tarball hash".into(),
            ));
        }
        if state_transaction
            .world
            .content_bundles
            .get(&bundle_id)
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "content bundle already exists".into(),
            ));
        }
        let chunk_size_bytes = config.chunk_size_bytes;
        let chunk_size = usize::try_from(chunk_size_bytes).unwrap_or(0);
        if chunk_size == 0 {
            return Err(Error::InvariantViolation(
                "content.chunk_size_bytes must be greater than zero".into(),
            ));
        }
        let files = parse_tar_index(
            &self.tarball,
            config.max_files,
            config.max_path_len,
            &state_transaction.content,
        )?;
        let manifest = build_manifest(bundle_id, &files, config, self.manifest.clone())?;
        if let Some(expiry) = self.expires_at_height {
            let current_height = state_transaction._curr_block.height().get();
            let max_expiry = current_height.saturating_add(config.max_retention_blocks);
            if expiry > max_expiry {
                return Err(Error::InvariantViolation(
                    format!(
                        "content bundle expiry exceeds configured retention window ({expiry} > {max_expiry})"
                    )
                    .into(),
                ));
            }
            if expiry < current_height {
                return Err(Error::InvariantViolation(
                    "content bundle expiry cannot be in the past".into(),
                ));
            }
        }
        let mut chunk_hashes = Vec::new();
        let mut offset = 0usize;
        while offset < self.tarball.len() {
            let end = (offset + chunk_size).min(self.tarball.len());
            let chunk = &self.tarball[offset..end];
            let hash = blake3_hash(chunk);
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            chunk_hashes.push(hash_bytes);
            if let Some(mut existing) = state_transaction
                .world
                .content_chunks
                .get(&hash_bytes)
                .cloned()
            {
                existing.inc();
                state_transaction
                    .world
                    .content_chunks
                    .insert(hash_bytes, existing);
            } else {
                state_transaction
                    .world
                    .content_chunks
                    .insert(hash_bytes, ContentChunk::new(chunk.to_vec()));
            }
            offset = end;
        }
        let chunk_root = compute_chunk_root(&chunk_hashes);
        let stripe_layout = manifest.stripe_layout;
        let record = ContentBundleRecord {
            bundle_id,
            manifest,
            total_bytes: tar_len,
            chunk_size: chunk_size_bytes,
            chunk_hashes,
            chunk_root,
            stripe_layout,
            pdp_commitment: None,
            files,
            created_by: authority.clone(),
            created_height: state_transaction._curr_block.height().get(),
            expires_at_height: self.expires_at_height,
        };
        state_transaction
            .world
            .content_bundles
            .insert(bundle_id, record);
        Ok(())
    }
}
impl Execute for iroha_data_model::isi::content::RetireContentBundle {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(record) = state_transaction
            .world
            .content_bundles
            .get(&self.bundle_id)
            .cloned()
        else {
            return Err(Error::InvariantViolation("content bundle not found".into()));
        };
        if record.created_by != *authority {
            return Err(Error::InvariantViolation(
                "only the content bundle creator may retire it".into(),
            ));
        }
        state_transaction
            .world
            .content_bundles
            .remove(self.bundle_id);
        for hash in &record.chunk_hashes {
            if let Some(mut chunk) = state_transaction.world.content_chunks.get(hash).cloned() {
                if chunk.dec_and_should_prune() {
                    state_transaction.world.content_chunks.remove(*hash);
                } else {
                    state_transaction.world.content_chunks.insert(*hash, chunk);
                }
            }
        }
        Ok(())
    }
}
fn build_manifest(
    bundle_id: Hash,
    files: &[ContentFileEntry],
    config: &iroha_config::parameters::actual::Content,
    provided: Option<ContentBundleManifest>,
) -> Result<ContentBundleManifest, Error> {
    let index_hash = hash_index(files)?;
    let default_cache = ContentCachePolicy {
        max_age_seconds: config
            .default_cache_max_age_secs
            .min(config.max_cache_max_age_secs)
            .max(1),
        immutable: config.immutable_bundles,
    };
    let mut manifest = if let Some(provided) = provided {
        if provided.bundle_id != bundle_id {
            return Err(Error::InvariantViolation(
                "manifest bundle_id does not match tarball hash".into(),
            ));
        }
        if provided.index_hash != index_hash {
            return Err(Error::InvariantViolation(
                "manifest index_hash does not match file index".into(),
            ));
        }
        provided
    } else {
        ContentBundleManifest {
            bundle_id,
            index_hash,
            dataspace: DataSpaceId::UNIVERSAL,
            lane: LaneId::SINGLE,
            blob_class: BlobClass::GovernanceArtifact,
            retention: RetentionPolicy::default(),
            cache: default_cache,
            auth: config.default_auth_mode.clone(),
            stripe_layout: config.stripe_layout,
            mime_overrides: BTreeMap::new(),
        }
    };
    manifest.bundle_id = bundle_id;
    manifest.index_hash = index_hash;
    if manifest.cache.max_age_seconds == 0 {
        manifest.cache.max_age_seconds = default_cache.max_age_seconds;
    }
    if manifest.cache.max_age_seconds > config.max_cache_max_age_secs {
        return Err(Error::InvariantViolation(
            format!(
                "cache max-age exceeds configured cap ({} > {})",
                manifest.cache.max_age_seconds, config.max_cache_max_age_secs
            )
            .into(),
        ));
    }
    manifest.cache.immutable |= config.immutable_bundles;
    if manifest.stripe_layout.total_stripes == 0 || manifest.stripe_layout.shards_per_stripe == 0 {
        manifest.stripe_layout = config.stripe_layout;
    }
    for path in manifest.mime_overrides.keys() {
        if !files.iter().any(|entry| &entry.path == path) {
            return Err(Error::InvariantViolation(
                format!("mime override references unknown path `{path}`").into(),
            ));
        }
    }
    Ok(manifest)
}
/// Compute the deterministic hash of a content file index using the canonical Norito encoding.
///
/// # Errors
///
/// Returns [`Error::InvariantViolation`] when encoding fails.
pub fn hash_index(files: &[ContentFileEntry]) -> Result<[u8; 32], Error> {
    let buf = Encode::encode(&files.to_vec());
    Ok(hash_bytes(&buf))
}
/// Public to allow tooling (CLI/xtask) to build manifests using the same parser.
///
/// # Errors
///
/// Returns [`Error`] when the tarball is malformed or exceeds configured limits.
pub fn parse_tar_index(
    tarball: &[u8],
    max_files: u32,
    max_path_len: u32,
    config: &iroha_config::parameters::actual::Content,
) -> Result<Vec<ContentFileEntry>, Error> {
    const HEADER_LEN: usize = 512;
    if tarball.len() < HEADER_LEN {
        return Err(Error::InvariantViolation(
            "tarball too small to contain header".into(),
        ));
    }
    let mut entries = Vec::new();
    let mut offset: usize = 0;
    while offset + HEADER_LEN <= tarball.len() {
        let header = &tarball[offset..offset + HEADER_LEN];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let name_raw = &header[0..100];
        let size_raw = &header[124..136];
        let typeflag = header[156];
        let prefix_raw = &header[345..500];
        if !matches!(typeflag, 0 | b'0') {
            return Err(Error::InvariantViolation(
                "only regular files are supported in content bundles".into(),
            ));
        }
        let name = parse_tar_string(name_raw)?;
        let prefix = parse_tar_string(prefix_raw)?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_empty() {
            return Err(Error::InvariantViolation("empty path in tar entry".into()));
        }
        let path_len = u32::try_from(path.len())
            .map_err(|_| Error::InvariantViolation("tar path length overflow".into()))?;
        if path_len > max_path_len {
            return Err(Error::InvariantViolation(
                format!("path exceeds max length ({path_len} > {max_path_len})").into(),
            ));
        }
        let size = parse_tar_size(size_raw)?;
        let data_start = offset
            .checked_add(HEADER_LEN)
            .ok_or_else(|| Error::InvariantViolation("tar header overflow".into()))?;
        let size_usize = usize::try_from(size)
            .map_err(|_| Error::InvariantViolation("tar payload size overflow".into()))?;
        let data_end = data_start
            .checked_add(size_usize)
            .ok_or_else(|| Error::InvariantViolation("tar payload overflow".into()))?;
        if data_end > tarball.len() {
            return Err(Error::InvariantViolation(
                "tar entry exceeds archive length".into(),
            ));
        }
        let payload = &tarball[data_start..data_end];
        let file_hash = hash_file(payload);
        entries.push(ContentFileEntry {
            path,
            offset: data_start as u64,
            length: size,
            file_hash,
        });
        let entry_count = u32::try_from(entries.len())
            .map_err(|_| Error::InvariantViolation("too many tar entries".into()))?;
        if entry_count > max_files {
            return Err(Error::InvariantViolation(
                "tarball exceeds maximum file count".into(),
            ));
        }
        let padding = size_usize.div_ceil(HEADER_LEN) * HEADER_LEN;
        offset = data_start + padding;
    }
    if entries.is_empty() {
        return Err(Error::InvariantViolation(
            "content bundle contains no files".into(),
        ));
    }
    if tarball.len() as u64 > config.max_bundle_bytes {
        return Err(Error::InvariantViolation(
            "content tarball exceeds configured size".into(),
        ));
    }
    Ok(entries)
}
fn parse_tar_string(bytes: &[u8]) -> Result<String, Error> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let raw = &bytes[..end];
    let s = str::from_utf8(raw)
        .map_err(|_| Error::InvariantViolation("tar header field is not utf-8".into()))?
        .trim()
        .to_string();
    Ok(s)
}
fn parse_tar_size(bytes: &[u8]) -> Result<u64, Error> {
    let trimmed = bytes
        .iter()
        .take_while(|b| b.is_ascii_digit() || **b == b' ')
        .copied()
        .collect::<Vec<_>>();
    let s = str::from_utf8(&trimmed)
        .map_err(|_| Error::InvariantViolation("tar size field invalid utf-8".into()))?
        .trim();
    u64::from_str_radix(s, 8)
        .map_err(|_| Error::InvariantViolation("invalid tar size field".into()))
}
fn hash_file(bytes: &[u8]) -> [u8; 32] {
    hash_bytes(bytes)
}
fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let hash = Hash::new(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}
fn compute_chunk_root(chunks: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        block::BlockHeader,
        da::prelude::DaStripeLayout,
        isi::content::{PublishContentBundle, RetireContentBundle},
        prelude::*,
    };
    use nonzero_ext::nonzero;
    fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        const HEADER_LEN: usize = 512;
        let mut out = Vec::new();
        for (name, data) in entries {
            let mut header = [0u8; HEADER_LEN];
            let name_bytes = name.as_bytes();
            header[..name_bytes.len()].copy_from_slice(name_bytes);
            // size field: octal, null-terminated
            let size_str = format!("{:0>11o}\0", data.len());
            header[124..124 + size_str.len()].copy_from_slice(size_str.as_bytes());
            header[156] = b'0';
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            // pad to 512
            let pad = (HEADER_LEN - (data.len() % HEADER_LEN)) % HEADER_LEN;
            out.resize(out.len() + pad, 0);
        }
        // two empty blocks terminator
        out.resize(out.len() + HEADER_LEN * 2, 0);
        out
    }
    fn checked_account_id() -> AccountId {
        let key_pair =
            KeyPair::try_random().expect("content fixture key generation should succeed");
        AccountId::new(key_pair.public_key().clone())
    }
    #[test]
    fn checked_account_id_preserves_default_algorithm() {
        let account_id = checked_account_id();
        assert_eq!(
            account_id.expect_single_signatory().algorithm(),
            Algorithm::default()
        );
    }
    #[test]
    fn publish_and_retire_content_bundle() {
        let tar = make_tar(&[("index.html", b"hi"), ("app.js", b"console.log(1);")]);
        let bundle_id = Hash::new(&tar);
        let world = World::default();
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(world, kura, query);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let publish = PublishContentBundle {
            bundle_id,
            tarball: tar.clone(),
            expires_at_height: None,
            manifest: None,
        };
        let authority = checked_account_id();
        publish
            .execute(&authority, &mut tx)
            .expect("publish content");
        let stored = tx.world.content_bundles.get(&bundle_id).cloned().unwrap();
        assert_eq!(stored.total_bytes, tar.len() as u64);
        assert_eq!(stored.files.len(), 2);
        assert_eq!(
            stored.manifest.index_hash,
            hash_index(&stored.files).expect("compute index hash")
        );
        assert_eq!(stored.manifest.cache.max_age_seconds, 300);
        assert!(stored.manifest.cache.immutable);
        assert!(!stored.chunk_hashes.is_empty());
        assert_eq!(stored.chunk_root, compute_chunk_root(&stored.chunk_hashes));
        assert_eq!(
            stored.stripe_layout,
            DaStripeLayout {
                total_stripes: 1,
                shards_per_stripe: 1,
                row_parity_stripes: 0,
            }
        );
        let retire = RetireContentBundle { bundle_id };
        retire.execute(&authority, &mut tx).expect("retire content");
        assert!(tx.world.content_bundles.get(&bundle_id).is_none());
        for hash in stored.chunk_hashes {
            assert!(tx.world.content_chunks.get(&hash).is_none());
        }
    }
    #[test]
    fn retire_content_bundle_rejects_non_creator() {
        let tar = make_tar(&[("index.html", b"creator-owned")]);
        let bundle_id = Hash::new(&tar);
        let world = World::default();
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(world, kura, query);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let creator = checked_account_id();
        let attacker = checked_account_id();
        assert_ne!(creator, attacker);
        PublishContentBundle {
            bundle_id,
            tarball: tar,
            expires_at_height: None,
            manifest: None,
        }
        .execute(&creator, &mut tx)
        .expect("creator publishes content");
        let stored = tx
            .world
            .content_bundles
            .get(&bundle_id)
            .cloned()
            .expect("published bundle");
        let error = (RetireContentBundle { bundle_id })
            .execute(&attacker, &mut tx)
            .expect_err("non-creator must not retire content");
        assert!(
            error
                .to_string()
                .contains("only the content bundle creator may retire it")
        );
        assert!(tx.world.content_bundles.get(&bundle_id).is_some());
        for hash in stored.chunk_hashes {
            assert!(tx.world.content_chunks.get(&hash).is_some());
        }
    }
}
