//! Explicit read-only candidate intake. A candidate is never source authority: the
//! compiler still synthesizes each current circuit and imports every matching key.
use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
    CATALOG_MAX_BYTES_V1, OriginalSinkV1, OriginalV1,
};
use iroha_core_zk::kagemusha_wallet_proofs_v1::Error;

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct ReuseRequest {
    schema: String,
    carrier_directory: String,
    scheme_id_hex: String,
    manifest_digest_hex: String,
    verifier_pack_sha256: String,
    producer_inventory_sha256: String,
}

pub(super) trait CarrierSource {
    fn directory(&self, digest: [u8; 32]) -> io::Result<&DirectoryOriginalsV1>;
}
impl CarrierSource for DirectoryOriginalsV1 {
    fn directory(&self, _: [u8; 32]) -> io::Result<&DirectoryOriginalsV1> {
        Ok(self)
    }
}

pub(super) struct Candidates {
    input: Original,
    root: PrivateDirectory,
    pack: Original,
    catalog: Original,
    directory: DirectoryOriginalsV1,
    identities: BTreeMap<[u8; 32], BlobV1>,
    originals: Vec<OriginalV1>,
}
impl Candidates {
    pub(super) fn load(path: &str) -> io::Result<Self> {
        let input = Original::open(path, REQUEST_MAX, None)?;
        let request: ReuseRequest = checked(
            json::from_slice(&input.bytes),
            "closed reuse request required",
        )?;
        if request.schema != "iroha.kagemusha.wallet-artifact-candidates.v1" {
            return Err(invalid("unsupported candidate input schema"));
        }
        let root = PrivateDirectory::open_exact(&request.carrier_directory)?;
        let pack = Original::open(
            root.path()
                .join("verifier-pack.norito")
                .to_str()
                .ok_or_else(|| invalid("candidate path"))?,
            iroha_core_zk::kagemusha_wallet_artifacts_v1::VERIFIER_PACK_MAX_BYTES_V1,
            Some(digest(&request.verifier_pack_sha256)?),
        )?;
        let catalog = Original::open(
            root.path()
                .join("producer-inventory.norito")
                .to_str()
                .ok_or_else(|| invalid("candidate path"))?,
            CATALOG_MAX_BYTES_V1,
            Some(digest(&request.producer_inventory_sha256)?),
        )?;
        let installed = InstalledVerifierPackV1::load(
            &pack.bytes,
            InstallationV1 {
                scheme_id: digest(&request.scheme_id_hex)?,
                manifest_digest: digest(&request.manifest_digest_hex)?,
            },
        )
        .map_err(io::Error::other)?;
        let inventory = installed
            .authenticate_producer_inventory(&catalog.bytes)
            .map_err(io::Error::other)?;
        let originals = inventory.inventory().originals.clone();
        let mut identities = BTreeMap::new();
        for original in &originals {
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
        }
        let directory = DirectoryOriginalsV1::open_existing(
            root.path().join("wallet-originals"),
            PROVING_KEY_MAX_BYTES_V1,
        )?;
        let candidates = Self {
            input,
            root,
            pack,
            catalog,
            directory,
            identities,
            originals,
        };
        candidates.recheck()?;
        Ok(candidates)
    }
    pub(super) fn recheck(&self) -> io::Result<()> {
        self.input.recheck()?;
        self.pack.recheck()?;
        self.catalog.recheck()?;
        self.root.revalidate()
    }
}

/// Retained candidates stay in their read-only directory. New compiler originals
/// go to this run's cache; the final carrier copies only the completed selection.
pub(super) struct CompilerSources {
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
            publish(
                output,
                "candidate-verifier-pack.norito",
                &candidates.pack.bytes,
            )?;
            publish(
                output,
                "candidate-producer-inventory.norito",
                &candidates.catalog.bytes,
            )?;
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

    #[test]
    fn explicit_candidate_input_refuses_missing_and_unknown_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let root = PrivateDirectory::open_or_create(
            temp.path().canonicalize().unwrap().join("candidate-input"),
        )
        .unwrap();
        let input = format!(
            r#"{{"schema":"iroha.kagemusha.wallet-artifact-candidates.v1","carrier_directory":"{}","scheme_id_hex":"{}","manifest_digest_hex":"{}","verifier_pack_sha256":"{}","producer_inventory_sha256":"{}"}}"#,
            root.path().display(),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32)
        );
        let parsed: ReuseRequest = json::from_slice(input.as_bytes()).unwrap();
        assert_eq!(parsed.carrier_directory, root.path().to_str().unwrap());
        assert!(
            json::from_slice::<ReuseRequest>(
                input.replacen('{', "{\"admitted\":true,", 1).as_bytes()
            )
            .is_err()
        );
        publish(&root, "input.json", input.as_bytes()).unwrap();
        assert!(Candidates::load(root.path().join("input.json").to_str().unwrap()).is_err());
        publish(&root, "verifier-pack.norito", b"tampered metadata").unwrap();
        assert!(Candidates::load(root.path().join("input.json").to_str().unwrap()).is_err());
    }

    #[test]
    fn candidate_routing_never_falls_back_for_missing_or_tampered_selected_original() {
        let temp = tempfile::tempdir().unwrap();
        let root =
            PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("routing"))
                .unwrap();
        let previous = root.create_child("previous").unwrap();
        let current = root.create_child("current").unwrap();
        for name in ["input", "pack", "catalog"] {
            publish(&previous, name, b"routing fixture only").unwrap();
        }
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
        // Only the private routing fixture bypasses signed-metadata loading; it grants nothing.
        let candidates = Candidates {
            input: original("input"),
            pack: original("pack"),
            catalog: original("catalog"),
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
