//! Bounded transport DATA exported only from the genuine completed wallet pack.

use std::{fmt::Write as _, io, path::Path};

use iroha_fs::PrivateDirectory;

use super::{BlobV1, WalletArtifactOriginalsV1};
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::{
    DirectoryOriginalsV1, encoded::financial_json, transport_metadata::publish_metadata,
};

const TRANSPORT_MAX_BYTES: usize = 32 * 1024 * 1024;
const PACK_MAX_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;
const CATALOG_MAX_BYTES: usize = 16 * 1024 * 1024;
const ORIGINAL_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const WALLET_MAX_ROWS: usize = 3 * 4096;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn rows(output: &mut String, originals: &[BlobV1], maximum: usize) -> io::Result<()> {
    if originals.len() > maximum {
        return Err(invalid("original transport row ceiling exceeded"));
    }
    let mut previous = None;
    output.push('[');
    for (index, blob) in originals.iter().enumerate() {
        if blob.bytes == 0
            || blob.bytes > ORIGINAL_MAX_BYTES
            || blob.sha256 == [0; 32]
            || previous.is_some_and(|digest| digest >= blob.sha256)
        {
            return Err(invalid(
                "original transport identity is not closed and ascending",
            ));
        }
        previous = Some(blob.sha256);
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"bytes\":{},\"sha256\":\"{}\"}}",
            blob.bytes,
            hex::encode(blob.sha256)
        )
        .map_err(|_| invalid("original transport encoding failed"))?;
        if output.len() > TRANSPORT_MAX_BYTES {
            return Err(invalid("original transport byte ceiling exceeded"));
        }
    }
    output.push(']');
    Ok(())
}

impl WalletArtifactOriginalsV1 {
    /// Raw compiler/candidate transport identities from the completed original graph.
    /// Mobile delivery uses the separately encoded carrier; it never accepts this form.
    /// No path, key, installed identity, authority flag or wallet-open grant is encoded.
    ///
    /// # Errors
    /// Invalid/nonascending identity, excessive row count or JSON byte ceiling.
    pub fn transport_json(&self) -> io::Result<Vec<u8>> {
        let mut output = String::from(
            "{\"schema\":\"iroha.kagemusha.wallet-artifact-original-transport.v1\",\"walletOriginals\":",
        );
        rows(&mut output, &self.wallet_originals, WALLET_MAX_ROWS)?;
        output.push_str("}\n");
        if output.len() > TRANSPORT_MAX_BYTES {
            return Err(invalid("original transport byte ceiling exceeded"));
        }
        Ok(output.into_bytes())
    }

    /// Exact bounded DATA for the signed application's financial-original selection.
    /// Derived only from this completed Native owner; never chooses a signature,
    /// installation ID, trust key or Ready state. Canonical JSON with one LF.
    /// # Errors
    /// Whole pack/catalog bounds, catalog commitment mismatch or transport closure failure.
    pub fn financial_originals_json(&self) -> io::Result<Vec<u8>> {
        if self.verifier_pack.is_empty()
            || self.verifier_pack.len() > PACK_MAX_BYTES
            || self.producer_inventory.is_empty()
            || self.producer_inventory.len() > CATALOG_MAX_BYTES
            || self.producer_catalog_digest == [0; 32]
            || self.producer_catalog_digest
                != crate::kagemusha_wallet_artifacts_v1::artifact_digest(
                    b"producer-catalog",
                    &self.producer_inventory,
                )
        {
            return Err(invalid("completed financial originals are inconsistent"));
        }
        financial_json(
            &self.verifier_pack,
            &self.producer_inventory,
            &self.transport_json()?,
        )
    }

    /// Export the four whole metadata originals into an existing private bundle root.
    /// The genuine compiler sink must be its `wallet-originals` child. Every referenced
    /// original is reauthenticated by a 64 KiB stream before metadata publication.
    /// Files are sealed 0400 before atomic no-replace publication. Exact retries retain
    /// original inodes; conflicts and partial publication evidence are preserved.
    ///
    /// # Errors
    /// Unsafe/missing/wrong ancestry, changed or absent original, bounds, conflict,
    /// unavailable storage/entropy or uncertain publication/durability. This export
    /// never authenticates signed genesis or grants Native installation authority.
    pub fn write_bundle_metadata(
        &self,
        root: impl AsRef<Path>,
        wallet: &DirectoryOriginalsV1,
    ) -> io::Result<()> {
        if self.verifier_pack.is_empty()
            || self.verifier_pack.len() > PACK_MAX_BYTES
            || self.producer_inventory.is_empty()
            || self.producer_inventory.len() > CATALOG_MAX_BYTES
        {
            return Err(invalid("whole metadata original byte ceiling exceeded"));
        }
        let transport = self.transport_json()?;
        let financial = self.financial_originals_json()?;
        let directory = PrivateDirectory::open_exact(root)?;
        if wallet.root()? != directory.path().join("wallet-originals") {
            return Err(invalid(
                "original graph does not belong to exact bundle roots",
            ));
        }
        for blob in &self.wallet_originals {
            wallet.verify_original(*blob)?;
        }
        directory.revalidate()?;
        publish_metadata(&directory, "verifier-pack.norito", &self.verifier_pack)?;
        publish_metadata(
            &directory,
            "producer-inventory.norito",
            &self.producer_inventory,
        )?;
        publish_metadata(&directory, "transport.json", &transport)?;
        publish_metadata(&directory, "financial-originals.json", &financial)?;
        wallet.root()?;
        directory.sync()?;
        directory.revalidate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_artifacts_v1::producer_inventory::transport_metadata::verify_metadata;
    use std::io::Write as _;

    // Explicit DATA fixtures exercise custody/export only, never compile or install
    // a production wallet. Production fields remain private and finish-only.
    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        DirectoryOriginalsV1,
        WalletArtifactOriginalsV1,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("bundle");
        PrivateDirectory::open_or_create(&root).unwrap();
        PrivateDirectory::open_or_create(root.join("wallet-originals")).unwrap();
        let root = root.canonicalize().unwrap();
        let mut wallet =
            DirectoryOriginalsV1::open_existing(root.join("wallet-originals"), 1024).unwrap();
        let one = BlobV1::of(b"actual wallet original");
        wallet
            .store_original(one, b"actual wallet original")
            .unwrap();
        let originals = WalletArtifactOriginalsV1 {
            producer_catalog_digest: crate::kagemusha_wallet_artifacts_v1::artifact_digest(
                b"producer-catalog",
                b"transport fixture whole inventory",
            ),
            verifier_pack: b"transport fixture whole pack".to_vec(),
            producer_inventory: b"transport fixture whole inventory".to_vec(),
            wallet_originals: vec![one],
        };
        (temp, root, wallet, originals)
    }

    #[test]
    fn identical_export_keeps_sealed_metadata_inodes_and_exact_originals() {
        let (_temp, root, wallet, originals) = fixture();
        originals.write_bundle_metadata(&root, &wallet).unwrap();
        let directory = PrivateDirectory::open_exact(&root).unwrap();
        let before = directory
            .open_retained_read_only("verifier-pack.norito", PACK_MAX_BYTES)
            .unwrap()
            .identity()
            .unwrap();
        originals.write_bundle_metadata(&root, &wallet).unwrap();
        let after = directory
            .open_retained_read_only("verifier-pack.norito", PACK_MAX_BYTES)
            .unwrap()
            .identity()
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            std::fs::read(root.join("verifier-pack.norito")).unwrap(),
            originals.verifier_pack
        );
        assert_eq!(
            std::fs::read(root.join("transport.json")).unwrap(),
            originals.transport_json().unwrap()
        );
        assert_eq!(
            std::fs::read(root.join("financial-originals.json")).unwrap(),
            originals.financial_originals_json().unwrap()
        );
    }

    #[test]
    fn metadata_initial_absence_never_masks_changed_directory_custody() {
        let (temp, root, _wallet, _originals) = fixture();
        let directory = PrivateDirectory::open_exact(&root).unwrap();
        let name = "metadata.norito";
        let bytes = b"exact retained metadata";
        assert_eq!(verify_metadata(&directory, name, bytes).unwrap(), None);
        publish_metadata(&directory, name, bytes).unwrap();
        assert_eq!(verify_metadata(&directory, name, bytes).unwrap(), Some(()));

        let retained = temp.path().join("retained-bundle");
        std::fs::rename(&root, &retained).unwrap();
        PrivateDirectory::open_or_create(&root).unwrap();
        assert!(verify_metadata(&directory, name, bytes).is_err());
        assert!(publish_metadata(&directory, name, bytes).is_err());
        assert!(!root.join(name).exists());
        assert_eq!(std::fs::read(retained.join(name)).unwrap(), bytes);
    }

    #[test]
    fn absent_actual_original_prevents_metadata_publication() {
        let (_temp, root, wallet, mut originals) = fixture();
        originals.wallet_originals[0] = BlobV1::of(b"missing authentic original");
        assert!(originals.write_bundle_metadata(&root, &wallet).is_err());
        assert!(!root.join("verifier-pack.norito").exists());
        assert!(!root.join("transport.json").exists());
    }

    #[test]
    fn transport_contains_only_wallet_circuits_and_refuses_missing_originals() {
        let (_temp, root, wallet, originals) = fixture();
        let json: norito::json::Value =
            norito::json::from_slice(&originals.transport_json().unwrap()).unwrap();
        assert!(json.as_object().unwrap().get("finalityOriginals").is_none());
        originals.write_bundle_metadata(&root, &wallet).unwrap();
        let blob = originals.wallet_originals[0];
        std::fs::remove_file(root.join("wallet-originals").join(hex::encode(blob.sha256))).unwrap();
        assert!(originals.write_bundle_metadata(&root, &wallet).is_err());
    }

    #[test]
    fn changed_required_verifier_original_refuses_before_metadata_publication() {
        let (_temp, root, wallet, originals) = fixture();
        let blob = BlobV1::of(b"actual wallet original");
        let path = root.join("wallet-originals").join(hex::encode(blob.sha256));
        std::fs::remove_file(&path).unwrap();
        // Equal extent and private permissions cannot authorize a changed preimage.
        let directory = PrivateDirectory::open_exact(root.join("wallet-originals")).unwrap();
        let mut writer = directory
            .create_retained_private(hex::encode(blob.sha256), blob.bytes as usize)
            .unwrap();
        writer.write_all(&vec![0; blob.bytes as usize]).unwrap();
        writer.seal_read_only().unwrap();
        assert!(originals.write_bundle_metadata(&root, &wallet).is_err());
        assert!(!root.join("verifier-pack.norito").exists());
    }

    #[test]
    fn wrong_graph_root_and_nonascending_transport_are_refused() {
        let (_temp, root, wallet, mut originals) = fixture();
        assert!(
            originals
                .write_bundle_metadata(root.parent().unwrap(), &wallet)
                .is_err()
        );
        let one = originals.wallet_originals[0];
        originals.wallet_originals.push(one);
        assert!(originals.transport_json().is_err());
        originals.wallet_originals = vec![BlobV1 {
            bytes: 1,
            sha256: [0; 32],
        }];
        assert!(originals.transport_json().is_err());
        originals.wallet_originals = vec![BlobV1 {
            bytes: ORIGINAL_MAX_BYTES + 1,
            sha256: [1; 32],
        }];
        assert!(originals.transport_json().is_err());
    }

    #[test]
    fn conflicting_partial_export_is_retained_and_never_overwritten() {
        let (_temp, root, wallet, originals) = fixture();
        let directory = PrivateDirectory::open_exact(&root).unwrap();
        let mut writer = directory
            .create_retained_private("producer-inventory.norito", 8)
            .unwrap();
        writer.write_all(b"conflict").unwrap();
        let sealed = writer.seal_read_only().unwrap();
        let before = sealed.identity().unwrap();
        assert!(originals.write_bundle_metadata(&root, &wallet).is_err());
        assert!(root.join("verifier-pack.norito").exists());
        assert!(!root.join("transport.json").exists());
        let existing = directory
            .open_retained_read_only("producer-inventory.norito", 8)
            .unwrap();
        assert_eq!(before, existing.identity().unwrap());
        assert_eq!(
            std::fs::read(root.join("producer-inventory.norito")).unwrap(),
            b"conflict"
        );
    }
    #[test]
    fn financial_data_is_exact_native_commitment_and_whole_transport_identity() {
        let (_temp, _root, _wallet, originals) = fixture();
        let bytes = originals.financial_originals_json().unwrap();
        let value: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 5);
        assert_eq!(
            object["schema"].as_str(),
            Some("iroha.kagemusha.wallet-financial-originals.v1")
        );
        assert_eq!(
            object["producerCatalogDigest"].as_str(),
            Some(hex::encode(originals.producer_catalog_digest).as_str())
        );
        for (name, actual) in [
            ("verifierPack", originals.verifier_pack.clone()),
            ("producerInventory", originals.producer_inventory.clone()),
            ("transport", originals.transport_json().unwrap()),
        ] {
            let blob = BlobV1::of(&actual);
            let row = object[name].as_object().unwrap();
            assert_eq!(row.len(), 2);
            assert_eq!(row["bytes"].as_u64(), Some(blob.bytes));
            assert_eq!(
                row["sha256"].as_str(),
                Some(hex::encode(blob.sha256).as_str())
            );
        }
        let mut canonical = norito::json::to_json_bounded(&value, 2048)
            .unwrap()
            .into_bytes();
        canonical.push(b'\n');
        assert_eq!(canonical, bytes);
    }
    #[test]
    fn changed_catalog_cannot_export_a_retained_native_commitment() {
        let (_temp, root, wallet, mut originals) = fixture();
        originals.producer_inventory[0] ^= 1;
        assert!(originals.financial_originals_json().is_err());
        assert!(originals.write_bundle_metadata(&root, &wallet).is_err());
        assert!(!root.join("financial-originals.json").exists());
        assert!(!root.join("verifier-pack.norito").exists());
    }
    #[test]
    fn conflicting_fourth_original_is_refused_without_replacing_its_inode() {
        let (_temp, root, wallet, originals) = fixture();
        let directory = PrivateDirectory::open_exact(&root).unwrap();
        let mut writer = directory
            .create_retained_private("financial-originals.json", 8)
            .unwrap();
        writer.write_all(b"conflict").unwrap();
        let sealed = writer.seal_read_only().unwrap();
        let before = sealed.identity().unwrap();
        assert!(originals.write_bundle_metadata(&root, &wallet).is_err());
        let existing = directory
            .open_retained_read_only("financial-originals.json", 8)
            .unwrap();
        assert_eq!(existing.identity().unwrap(), before);
        assert_eq!(
            std::fs::read(root.join("financial-originals.json")).unwrap(),
            b"conflict"
        );
        assert_eq!(
            std::fs::read(root.join("transport.json")).unwrap(),
            originals.transport_json().unwrap()
        );
    }
}
