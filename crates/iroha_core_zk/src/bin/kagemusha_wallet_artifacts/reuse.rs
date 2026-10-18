//! Explicit read-only candidate intake. A candidate is never source authority: the
//! compiler still synthesizes each current circuit and imports every matching key.
use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    DESCRIPTOR_MAX_BYTES_V1, VERIFYING_KEY_MAX_BYTES_V1,
    producer_inventory::{ARTIFACT_MAX_COUNT_V1, OriginalSinkV1, OriginalV1},
};
use iroha_core_zk::kagemusha_wallet_proofs_v1::Error;

const CANDIDATE_REQUEST_MAX: usize = 4 << 20;

#[derive(Clone, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CandidateBlob {
    bytes: u64,
    sha256: String,
}
impl CandidateBlob {
    fn identity(&self, maximum: usize) -> io::Result<BlobV1> {
        if self.bytes == 0 || self.bytes > maximum as u64 {
            return Err(invalid("candidate role extent outside limit"));
        }
        Ok(BlobV1 {
            bytes: self.bytes,
            sha256: digest(&self.sha256)?,
        })
    }
}

#[derive(Clone, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CandidateOriginal {
    descriptor: CandidateBlob,
    verifying_key: CandidateBlob,
    proving_key: CandidateBlob,
}

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ReuseRequest {
    schema: String,
    originals_directory: String,
    originals: Vec<CandidateOriginal>,
}

/// A bounded exact lookup list, never a verifier installation or source grant.
/// The current compiler independently matches source fingerprints and imports every
/// selected original, including all source and commitment checks, before signing.
fn selected_originals(request: &ReuseRequest) -> io::Result<Vec<OriginalV1>> {
    if request.schema != "iroha.kagemusha.wallet-artifact-candidates.v1"
        || request.originals.is_empty()
        || request.originals.len() > ARTIFACT_MAX_COUNT_V1
    {
        return Err(invalid("unsupported candidate schema or original count"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut identities = BTreeMap::new();
    let mut originals = Vec::with_capacity(request.originals.len());
    for row in &request.originals {
        let original = OriginalV1 {
            descriptor: row.descriptor.identity(DESCRIPTOR_MAX_BYTES_V1)?,
            verifying_key: row.verifying_key.identity(VERIFYING_KEY_MAX_BYTES_V1)?,
            proving_key: row.proving_key.identity(PROVING_KEY_MAX_BYTES_V1)?,
        };
        if !seen.insert((
            original.descriptor.sha256,
            original.verifying_key.sha256,
            original.proving_key.sha256,
        )) {
            return Err(invalid("duplicate candidate original"));
        }
        for blob in [
            original.descriptor,
            original.verifying_key,
            original.proving_key,
        ] {
            if identities
                .insert(blob.sha256, blob)
                .is_some_and(|old| old != blob)
            {
                return Err(invalid("ambiguous candidate identity"));
            }
        }
        originals.push(original);
    }
    Ok(originals)
}

/// Select retained original directories without granting source or verifier authority.
pub trait CarrierSource {
    /// Locate the retained directory selected for this original digest.
    ///
    /// # Errors
    /// Returns an error if retained candidate input or directory custody fails revalidation.
    fn directory(&self, digest: [u8; 32]) -> io::Result<&DirectoryOriginalsV1>;
}
impl CarrierSource for DirectoryOriginalsV1 {
    fn directory(&self, _: [u8; 32]) -> io::Result<&DirectoryOriginalsV1> {
        Ok(self)
    }
}

/// Retained read-only candidate inputs awaiting the compiler's independent source checks.
pub struct Candidates {
    input: Original,
    root: PrivateDirectory,
    directory: DirectoryOriginalsV1,
    identities: BTreeMap<[u8; 32], BlobV1>,
    originals: Vec<OriginalV1>,
}
impl Candidates {
    pub(super) fn load(path: &str) -> io::Result<Self> {
        let input = Original::open(path, CANDIDATE_REQUEST_MAX, None)?;
        let request: ReuseRequest = checked(
            json::from_slice(&input.bytes),
            "closed reuse request required",
        )?;
        let originals = selected_originals(&request)?;
        let root = PrivateDirectory::open_exact(&request.originals_directory)?;
        let identities = originals
            .iter()
            .flat_map(|original| {
                [
                    original.descriptor,
                    original.verifying_key,
                    original.proving_key,
                ]
            })
            .map(|blob| (blob.sha256, blob))
            .collect();
        let directory = DirectoryOriginalsV1::open_existing(root.path(), PROVING_KEY_MAX_BYTES_V1)?;
        let candidates = Self {
            input,
            root,
            directory,
            identities,
            originals,
        };
        candidates.recheck()?;
        Ok(candidates)
    }
    pub(super) fn recheck(&self) -> io::Result<()> {
        self.input.recheck()?;
        self.root.revalidate()
    }
}

/// Retained candidates stay in their read-only directory. New compiler originals
/// go to this run's cache; the final carrier copies only the completed selection.
pub struct CompilerSources {
    current: DirectoryOriginalsV1,
    candidates: Option<Candidates>,
}
impl CompilerSources {
    pub(super) fn new(current: DirectoryOriginalsV1, candidates: Option<Candidates>) -> Self {
        Self {
            current,
            candidates,
        }
    }
    pub(super) fn candidate_originals(&self) -> Vec<OriginalV1> {
        self.candidates
            .as_ref()
            .map_or_else(Vec::new, |value| value.originals.clone())
    }
    pub(super) fn recheck(&self) -> io::Result<()> {
        self.candidates.as_ref().map_or(Ok(()), Candidates::recheck)
    }
    pub(super) fn retain_inputs(&self, output: &PrivateDirectory) -> io::Result<()> {
        if let Some(candidates) = &self.candidates {
            candidates.recheck()?;
            publish(output, "reuse-candidates.json", &candidates.input.bytes)?;
            candidates.recheck()?;
        }
        Ok(())
    }
}
impl CarrierSource for CompilerSources {
    fn directory(&self, digest: [u8; 32]) -> io::Result<&DirectoryOriginalsV1> {
        if let Some(candidates) = &self.candidates {
            candidates.recheck()?;
            if candidates.identities.contains_key(&digest) {
                return Ok(&candidates.directory);
            }
        }
        Ok(&self.current)
    }
}
impl OriginalSourceV1 for CompilerSources {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.directory(digest)
            .map_err(|_| Error::Unavailable)?
            .open_original(digest)
    }
}
impl OriginalSinkV1 for CompilerSources {
    fn store(&mut self, identity: BlobV1, bytes: &[u8]) -> Result<(), Error> {
        OriginalSinkV1::store(&mut self.current, identity, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_row() -> CandidateOriginal {
        let blob = |byte| CandidateBlob {
            bytes: 1,
            sha256: hex::encode(BlobV1::of(&[byte]).sha256),
        };
        CandidateOriginal {
            descriptor: blob(1),
            verifying_key: blob(2),
            proving_key: blob(3),
        }
    }

    fn request(originals: Vec<CandidateOriginal>) -> ReuseRequest {
        ReuseRequest {
            schema: "iroha.kagemusha.wallet-artifact-candidates.v1".into(),
            originals_directory: "/unopened-candidate-data".into(),
            originals,
        }
    }

    #[test]
    fn explicit_candidate_input_is_closed_and_does_not_accept_retired_authority_fields() {
        let input = format!(
            r#"{{"schema":"iroha.kagemusha.wallet-artifact-candidates.v1","originals_directory":"/unopened-candidate-data","originals":[{{"descriptor":{{"bytes":1,"sha256":"{}"}},"verifying_key":{{"bytes":2,"sha256":"{}"}},"proving_key":{{"bytes":3,"sha256":"{}"}}}}]}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        );
        let parsed: ReuseRequest = json::from_slice(input.as_bytes()).unwrap();
        assert_eq!(selected_originals(&parsed).unwrap().len(), 1);
        for extra in [
            r#""admitted":true,"#,
            r#""scheme_id_hex":"old","#,
            r#""carrier_directory":"/old","#,
            r#""original_groups":["sigma"],"#,
        ] {
            assert!(
                json::from_slice::<ReuseRequest>(
                    input.replacen('{', &format!("{{{extra}"), 1).as_bytes()
                )
                .is_err()
            );
        }
        assert!(
            json::from_slice::<ReuseRequest>(
                input.replace("\"bytes\":1", "\"bytes\":true").as_bytes()
            )
            .is_err()
        );
        assert!(
            json::from_slice::<ReuseRequest>(
                input
                    .replace("\"bytes\":1", "\"bytes\":1,\"ready\":true")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            json::from_slice::<ReuseRequest>(
                input.replace("\"descriptor\":", "\"unknown\":").as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_selection_bounds_roles_and_refuses_duplicate_or_ambiguous_identities() {
        assert!(selected_originals(&request(Vec::new())).is_err());
        assert!(
            selected_originals(&request(vec![candidate_row(); ARTIFACT_MAX_COUNT_V1 + 1])).is_err()
        );
        assert!(selected_originals(&request(vec![candidate_row(), candidate_row()])).is_err());
        for role in 0..3 {
            for bytes in [
                0,
                1 + [
                    DESCRIPTOR_MAX_BYTES_V1,
                    VERIFYING_KEY_MAX_BYTES_V1,
                    PROVING_KEY_MAX_BYTES_V1,
                ][role] as u64,
            ] {
                let mut row = candidate_row();
                [
                    &mut row.descriptor,
                    &mut row.verifying_key,
                    &mut row.proving_key,
                ][role]
                    .bytes = bytes;
                assert!(selected_originals(&request(vec![row])).is_err());
            }
        }
        let mut shared = candidate_row();
        shared.proving_key.sha256 = "44".repeat(32);
        assert_eq!(
            selected_originals(&request(vec![candidate_row(), shared.clone()]))
                .unwrap()
                .len(),
            2
        );
        shared.descriptor.bytes += 1;
        assert!(selected_originals(&request(vec![candidate_row(), shared])).is_err());
        for hash in ["00".repeat(32), "AA".repeat(32), "../not-a-digest".into()] {
            let mut row = candidate_row();
            row.proving_key.sha256 = hash;
            assert!(selected_originals(&request(vec![row])).is_err());
        }
        let mut wrong_schema = request(vec![candidate_row()]);
        wrong_schema.schema.push_str("-other");
        assert!(selected_originals(&wrong_schema).is_err());
    }

    #[test]
    fn candidate_manifest_is_retained_and_files_remain_untrusted_until_compiler_import() {
        let temp = tempfile::tempdir().unwrap();
        let root = PrivateDirectory::open_or_create(
            temp.path().canonicalize().unwrap().join("candidate-input"),
        )
        .unwrap();
        let originals = root.create_child("originals").unwrap();
        let row = candidate_row();
        for (data, blob) in [
            (1, &row.descriptor),
            (2, &row.verifying_key),
            (3, &row.proving_key),
        ] {
            publish(&originals, &blob.sha256, &[data]).unwrap();
        }
        let input = format!(
            r#"{{"schema":"iroha.kagemusha.wallet-artifact-candidates.v1","originals_directory":"{}","originals":[{{"descriptor":{{"bytes":1,"sha256":"{}"}},"verifying_key":{{"bytes":1,"sha256":"{}"}},"proving_key":{{"bytes":1,"sha256":"{}"}}}}]}}"#,
            originals.path().display(),
            row.descriptor.sha256,
            row.verifying_key.sha256,
            row.proving_key.sha256,
        );
        publish(&root, "input.json", input.as_bytes()).unwrap();
        let loaded = Candidates::load(root.path().join("input.json").to_str().unwrap()).unwrap();
        assert_eq!(loaded.originals.len(), 1);
        let cache = root.create_child("cache").unwrap();
        let mut source = CompilerSources::new(
            DirectoryOriginalsV1::open_existing(cache.path(), PROVING_KEY_MAX_BYTES_V1).unwrap(),
            Some(loaded),
        );
        let output = root.create_child("retained").unwrap();
        source.retain_inputs(&output).unwrap();
        assert_eq!(
            std::fs::read(output.path().join("reuse-candidates.json")).unwrap(),
            input.as_bytes()
        );
        // Valid content hashes and a manifest do not turn these arbitrary bytes into a key.
        let scope = SourceScopeV1::new([1, 2], Affine::GENERATOR).unwrap();
        let config = ReadConfig {
            maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        let selected = source.candidate_originals();
        let mut compiler = OfflineCompilerV1::new(scope, &mut source, config, OUTPUT_MAX).unwrap();
        assert!(compiler.index_original(selected[0]).is_err());
        drop(compiler);
        std::fs::remove_file(root.path().join("input.json")).unwrap();
        publish(&root, "input.json", input.as_bytes()).unwrap();
        assert!(source.recheck().is_err());
    }

    #[test]
    fn candidate_routing_never_falls_back_for_missing_or_tampered_selected_original() {
        let temp = tempfile::tempdir().unwrap();
        let root =
            PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("routing"))
                .unwrap();
        let previous = root.create_child("previous").unwrap();
        let current = root.create_child("current").unwrap();
        publish(&previous, "input", b"routing fixture only").unwrap();
        let original =
            |name| Original::open(previous.path().join(name).to_str().unwrap(), 100, None).unwrap();
        let mut directory = DirectoryOriginalsV1::open_existing(previous.path(), 1024).unwrap();
        let mut fresh = DirectoryOriginalsV1::open_existing(current.path(), 1024).unwrap();
        let selected = BlobV1::of(b"candidate original");
        directory
            .store_original(selected, b"candidate original")
            .unwrap();
        fresh
            .store_original(selected, b"candidate original")
            .unwrap();
        // Only this private routing fixture constructs the lookup owner directly; it grants nothing.
        let candidates = Candidates {
            input: original("input"),
            root: previous,
            directory,
            identities: BTreeMap::from([(selected.sha256, selected)]),
            originals: Vec::new(),
        };
        let mut source = CompilerSources::new(fresh, Some(candidates));
        let output = root.create_child("completed").unwrap();
        copy_closed(&source, &output, &[selected]).unwrap();
        assert!(
            source
                .directory(selected.sha256)
                .unwrap()
                .verify_original(selected)
                .is_ok()
        );
        let path = source
            .candidates
            .as_ref()
            .unwrap()
            .root
            .path()
            .join(hex::encode(selected.sha256));
        std::fs::remove_file(&path).unwrap();
        assert!(source.open(selected.sha256).is_err());
        // A good current-cache copy must not conceal loss of the named candidate original.
        source.current.verify_original(selected).unwrap();
        let output = root.create_child("missing").unwrap();
        assert!(copy_closed(&source, &output, &[selected]).is_err());
        publish(
            &source.candidates.as_ref().unwrap().root,
            &hex::encode(selected.sha256),
            b"tampered original",
        )
        .unwrap();
        let output = root.create_child("tampered").unwrap();
        assert!(copy_closed(&source, &output, &[selected]).is_err());
    }
}
