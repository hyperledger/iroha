//! Production packaging from the complete real offline wallet source compilation.
//!
//! The only draft constructor runs `OfflineCompilerV1::wallet`, with all original
//! strict imports and final-key closure. Root/artifact signatures are supplied as
//! original canonical frames and verified against the exact generated bodies. No
//! signer, release key, engineering fixture or wallet-open grant exists here.

use iroha_plonk_gadgets::p256::native::words_to_be;

use super::*;

#[path = "pack/transport.rs"]
mod transport;

/// Complete unsigned wallet metadata awaiting its real existing authority signatures.
/// This draft is packaging DATA, never an authenticated installation capability.
pub struct WalletArtifactDraftV1 {
    pack: VerifierPackV1,
    scheme: KagemushaWalletSchemeV1,
    runtime: RuntimeBindings,
    key_set: [u8; 32],
    catalog: Vec<u8>,
    wallet_originals: Vec<BlobV1>,
}

/// Exact signed original pack and complete catalog returned after body/signature checks.
/// Native installation still needs independently admitted identities, signed genesis
/// and the complete original source qualification; this supplies none of those grants.
pub struct WalletArtifactOriginalsV1 {
    producer_catalog_digest: [u8; 32],
    verifier_pack: Vec<u8>,
    producer_inventory: Vec<u8>,
    wallet_originals: Vec<BlobV1>,
}

impl WalletArtifactOriginalsV1 {
    /// Whole canonical `VerifierPackV1` original, with all sixteen sigma keys and Omega.
    pub fn verifier_pack(&self) -> &[u8] {
        &self.verifier_pack
    }

    /// Whole canonical `ProducerInventoryV1` original whose digest is signed in the pack.
    pub fn producer_inventory(&self) -> &[u8] {
        &self.producer_inventory
    }

    /// Closed, ascending exact SHA/length references emitted by the actual wallet compiler.
    /// This is transport DATA. Never enumerate a directory containing retained partial files.
    pub fn wallet_originals(&self) -> &[BlobV1] {
        &self.wallet_originals
    }
}

fn closed_blobs(
    originals: impl IntoIterator<Item = (BlobV1, usize)>,
) -> Result<Vec<BlobV1>, Error> {
    let mut closed = BTreeMap::new();
    for (blob, bound) in originals {
        blob.length(bound)?;
        if closed
            .insert(blob.sha256, blob)
            .is_some_and(|previous| previous != blob)
        {
            return Err(Error::Inventory);
        }
    }
    Ok(closed.into_values().collect())
}

fn source_root(scope: SourceScopeV1) -> Result<KagemushaDevicePublicKeyV1, CompilationErrorV1> {
    let mut bytes = [0_u8; 65];
    bytes[0] = 4;
    bytes[1..33].copy_from_slice(&words_to_be(&scope.root().x));
    bytes[33..65].copy_from_slice(&words_to_be(&scope.root().y));
    KagemushaDevicePublicKeyV1::from_sec1_bytes(&bytes).map_err(|_| CompilationErrorV1::Closure)
}

fn raw_scheme(
    scope: SourceScopeV1,
    network: [u8; 32],
    relation: [u8; 32],
) -> Result<KagemushaWalletSchemeV1, CompilationErrorV1> {
    let provider = kagemusha_wallet_provider_contract_v1();
    let limbs = [
        u128::from_le_bytes(
            provider[..16]
                .try_into()
                .map_err(|_| CompilationErrorV1::Closure)?,
        ),
        u128::from_le_bytes(
            provider[16..]
                .try_into()
                .map_err(|_| CompilationErrorV1::Closure)?,
        ),
    ];
    if scope.provider() != limbs {
        return Err(CompilationErrorV1::Closure);
    }
    let scheme = KagemushaWalletSchemeV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        network_id: network,
        scheme_root_key: source_root(scope)?,
        relation_id: relation,
        provider_contract: provider,
    };
    scheme.validate().map_err(|_| CompilationErrorV1::Closure)?;
    Ok(scheme)
}

impl OfflineCompilerV1<'_> {
    /// Compile every current wallet route and assemble its real unsigned verifier pack.
    /// Partial original files remain retained on failure. Only actual compiled metadata
    /// is used; no caller inventory or replacement descriptor/key can construct the draft.
    ///
    /// # Errors
    /// Wrong compiled provider/network/root, any complete source/import/closure failure,
    /// missing or changed exact metadata original, incomplete catalog or profile mismatch.
    pub fn wallet_pack(
        &mut self,
        network: [u8; 32],
    ) -> Result<WalletArtifactDraftV1, CompilationErrorV1> {
        let mut scheme = raw_scheme(self.scope, network, [1; 32])?;
        let inventory = self.wallet()?;
        inventory.validate()?;
        let catalog = inventory.to_canonical_bytes()?;
        let wallet_originals = closed_blobs(inventory.originals.iter().flat_map(|original| {
            [
                (original.descriptor, DESCRIPTOR_MAX_BYTES_V1),
                (original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1),
                (original.proving_key, PROVING_KEY_MAX_BYTES_V1),
            ]
        }))?;
        let mut artifact = |index: u32| -> Result<ArtifactOriginalV1, CompilationErrorV1> {
            let original = *inventory.member(index)?;
            Ok(ArtifactOriginalV1 {
                descriptor: read(self.sink, original.descriptor, DESCRIPTOR_MAX_BYTES_V1)?,
                verifying_key: read(
                    self.sink,
                    original.verifying_key,
                    VERIFYING_KEY_MAX_BYTES_V1,
                )?,
            })
        };
        let mut steps = Vec::with_capacity(SIGMA_CATALOG_V1.len());
        let mut entries = Vec::with_capacity(SIGMA_CATALOG_V1.len());
        for ((tag, controls), index) in SIGMA_CATALOG_V1.into_iter().zip(inventory.sigma) {
            let kind = KagemushaWalletOperationKindV1::ALL
                .iter()
                .copied()
                .find(|kind| kind.tag() == tag)
                .ok_or(CompilationErrorV1::Closure)?;
            let original = artifact(index)?;
            let parsed = parse_artifact::<Eq>(&original, false)?;
            entries.push(KagemushaWalletVerifyingKeyEntryV1 {
                kind,
                enabled_controls: controls,
                verifying_key_digest: parsed.verifying_key_digest,
                proof_bytes: parsed.proof_bytes,
            });
            steps.push(StepOriginalV1 {
                kind,
                enabled_controls: controls,
                artifact: original,
            });
        }
        let lineage = artifact(inventory.omega)?;
        let omega = parse_artifact::<Ep>(&lineage, true)?;
        let allowlist = KagemushaWalletVerifyingKeyAllowlistV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            steps: entries,
            lineage_verifying_key_digest: omega.verifying_key_digest,
            lineage_proof_bytes: omega.proof_bytes,
        };
        let key_set = allowlist
            .verifying_key_set_digest()
            .map_err(|_| CompilationErrorV1::Closure)?;
        let pack = VerifierPackV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme: Vec::new(),
            signer_certificate: Vec::new(),
            manifest: Vec::new(),
            allowlist: norito::encode_canonical(&allowlist)
                .map_err(|_| CompilationErrorV1::Closure)?,
            steps,
            lineage,
            producer_catalog_digest: artifact_digest(b"producer-catalog", &catalog),
        };
        let runtime = pack.runtime_bindings()?;
        scheme.relation_id = kagemusha_wallet_relation_id_v1(
            &runtime.eq_protocol_digest,
            &runtime.ep_protocol_digest,
            &runtime.native_profile_digest,
            &key_set,
            &runtime.artifact_inventory_digest,
        );
        scheme.validate().map_err(|_| CompilationErrorV1::Closure)?;
        // Reconstruct the exact raw source policy from the completed scheme. The new
        // relation/inventory identity cannot change the root/provider used by keygen.
        if SourceScopeV1::from_scheme(&scheme)? != self.scope {
            return Err(CompilationErrorV1::Closure);
        }
        Ok(WalletArtifactDraftV1 {
            pack,
            scheme,
            runtime,
            key_set,
            catalog,
            wallet_originals,
        })
    }
}

impl WalletArtifactDraftV1 {
    /// Exact unsigned inventory from the completed source compiler, for durable
    /// retention before signing. This original is data and grants no installation.
    pub fn producer_inventory(&self) -> &[u8] {
        &self.catalog
    }

    /// Exact generated Scheme body for the existing root/certificate authority workflow.
    pub const fn scheme(&self) -> &KagemushaWalletSchemeV1 {
        &self.scheme
    }

    /// Derive the sole manifest body after authenticating an actual Artifact certificate.
    /// This uses the current protocol's signatures and adds no approval ceremony.
    ///
    /// # Errors
    /// Noncanonical/wrong-scheme certificate, wrong role or invalid root signature.
    pub fn manifest_body(
        &self,
        certificate_original: &[u8],
    ) -> Result<KagemushaWalletArtifactManifestBodyV1, Error> {
        let certificate = KagemushaWalletSignerCertificateV1::decode_canonical(
            certificate_original,
            &self.scheme,
        )
        .map_err(|_| Error::Authority)?;
        certificate
            .verify_role(&self.scheme, KagemushaWalletSignerRoleV1::Artifact)
            .map_err(|_| Error::Authority)?;
        Ok(KagemushaWalletArtifactManifestBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            network_id: self.scheme.network_id,
            relation_id: self.scheme.relation_id,
            eq_protocol_digest: self.runtime.eq_protocol_digest,
            ep_protocol_digest: self.runtime.ep_protocol_digest,
            native_profile_digest: self.runtime.native_profile_digest,
            verifying_key_set_digest: self.key_set,
            artifact_inventory_digest: self.runtime.artifact_inventory_digest,
            provider_contract: self.scheme.provider_contract,
            signer_certificate: certificate.certificate_digest(),
        })
    }

    /// Bind genuine existing root/artifact signatures to the complete compiled originals.
    /// The result is canonical packaging DATA, with no independently installed identity.
    ///
    /// # Errors
    /// Changed certificate or manifest body, invalid authentic signature or codec/bound error.
    pub fn finish(
        mut self,
        certificate_original: &[u8],
        manifest_original: &[u8],
    ) -> Result<WalletArtifactOriginalsV1, Error> {
        let expected = self.manifest_body(certificate_original)?;
        let certificate = KagemushaWalletSignerCertificateV1::decode_canonical(
            certificate_original,
            &self.scheme,
        )
        .map_err(|_| Error::Authority)?;
        let manifest =
            KagemushaWalletArtifactManifestV1::decode_canonical(manifest_original, &self.scheme)
                .map_err(|_| Error::Authority)?;
        if manifest.body != expected {
            return Err(Error::RuntimeBinding);
        }
        manifest
            .verify(&self.scheme, &certificate)
            .map_err(|_| Error::Authority)?;
        self.pack.scheme = self
            .scheme
            .to_canonical_bytes()
            .map_err(|_| Error::Authority)?;
        self.pack.signer_certificate = certificate_original.to_vec();
        self.pack.manifest = manifest_original.to_vec();
        Ok(WalletArtifactOriginalsV1 {
            producer_catalog_digest: self.pack.producer_catalog_digest,
            verifier_pack: self.pack.to_canonical_bytes()?,
            producer_inventory: self.catalog,
            wallet_originals: self.wallet_originals,
        })
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use std::sync::OnceLock;

    use super::*;

    // These explicit engineering originals test only the authentic certificate/body
    // packaging boundary. They never test or substitute complete wallet source compilation.
    fn fixture() -> (WalletArtifactDraftV1, VerifierPackV1) {
        static ORIGINAL: OnceLock<(VerifierPackV1, InstallationV1)> = OnceLock::new();
        let (pack, installation) = ORIGINAL.get_or_init(engineering_fixture::signed_inventory);
        let scheme =
            KagemushaWalletSchemeV1::decode_canonical(&pack.scheme, &installation.scheme_id)
                .unwrap();
        let allowlist: KagemushaWalletVerifyingKeyAllowlistV1 =
            norito::decode_canonical(&pack.allowlist).unwrap();
        (
            WalletArtifactDraftV1 {
                pack: pack.clone(),
                scheme,
                runtime: pack.runtime_bindings().unwrap(),
                key_set: allowlist.verifying_key_set_digest().unwrap(),
                catalog: b"engineering-verifier-only".to_vec(),
                wallet_originals: Vec::new(),
            },
            pack.clone(),
        )
    }

    fn signature(key: &SigningKey, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
        let result: Signature = key.sign(message);
        KagemushaWalletSignerOutputV1::Raw(result.to_bytes().into())
    }

    #[test]
    fn authentic_originals_keep_the_whole_exact_signed_pack() {
        let (draft, pack) = fixture();
        assert_eq!(draft.producer_inventory(), b"engineering-verifier-only");
        let result = draft
            .finish(&pack.signer_certificate, &pack.manifest)
            .unwrap();
        assert_eq!(result.verifier_pack(), pack.to_canonical_bytes().unwrap());
        assert_eq!(result.producer_inventory(), b"engineering-verifier-only");
    }

    #[test]
    fn an_authentic_signature_over_another_inventory_is_rejected() {
        let (draft, pack) = fixture();
        let certificate = KagemushaWalletSignerCertificateV1::decode_canonical(
            &pack.signer_certificate,
            draft.scheme(),
        )
        .unwrap();
        let mut body = draft.manifest_body(&pack.signer_certificate).unwrap();
        body.artifact_inventory_digest[0] ^= 1;
        body.relation_id = kagemusha_wallet_relation_id_v1(
            &body.eq_protocol_digest,
            &body.ep_protocol_digest,
            &body.native_profile_digest,
            &body.verifying_key_set_digest,
            &body.artifact_inventory_digest,
        );
        body.validate().unwrap();
        let key = SigningKey::from_bytes((&[0x18; 32]).into()).unwrap();
        let manifest = KagemushaWalletArtifactManifestV1::sign(
            body,
            &certificate,
            signature(&key, &body.signing_message()),
        )
        .unwrap();
        manifest.validate().unwrap();
        assert!(manifest.verify(draft.scheme(), &certificate).is_err());
        assert_eq!(
            draft
                .finish(
                    &pack.signer_certificate,
                    &manifest.to_canonical_bytes().unwrap()
                )
                .err(),
            Some(Error::Authority)
        );
    }

    #[test]
    fn enrollment_certificates_cannot_authorize_artifact_manifests() {
        let (draft, pack) = fixture();
        let mut body = KagemushaWalletSignerCertificateV1::decode_canonical(
            &pack.signer_certificate,
            draft.scheme(),
        )
        .unwrap()
        .body;
        body.role = KagemushaWalletSignerRoleV1::Enrollment;
        let root = SigningKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let certificate = KagemushaWalletSignerCertificateV1::sign(
            body,
            draft.scheme(),
            signature(&root, &body.signing_message()),
        )
        .unwrap();
        certificate.verify(draft.scheme()).unwrap();
        assert!(
            draft
                .manifest_body(&certificate.to_canonical_bytes().unwrap())
                .is_err()
        );
    }

    #[test]
    fn source_provider_and_native_network_are_checked_before_compilation() {
        let (draft, _) = fixture();
        let scope = SourceScopeV1::from_scheme(draft.scheme()).unwrap();
        assert!(raw_scheme(scope, draft.scheme.network_id, [1; 32]).is_ok());
        let wrong = SourceScopeV1::new([1, 2], scope.root()).unwrap();
        assert!(raw_scheme(wrong, draft.scheme.network_id, [1; 32]).is_err());
        assert!(raw_scheme(scope, [0; 32], [1; 32]).is_err());
    }

    #[test]
    fn transport_closure_deduplicates_exact_originals_and_refuses_changed_extents() {
        let one = BlobV1::of(b"one");
        let two = BlobV1::of(b"two");
        let closed = closed_blobs([(one, 3), (two, 3), (one, 3)]).unwrap();
        assert_eq!(closed.len(), 2);
        assert!(
            closed
                .windows(2)
                .all(|pair| pair[0].sha256 < pair[1].sha256)
        );
        assert!(closed.contains(&one) && closed.contains(&two));
        assert_eq!(closed_blobs([(one, 2)]).err(), Some(Error::Inventory));
        assert_eq!(
            closed_blobs([(one, 4), (BlobV1 { bytes: 4, ..one }, 4)]).err(),
            Some(Error::Inventory)
        );
        assert_eq!(
            closed_blobs([(BlobV1::of(b""), 1)]).err(),
            Some(Error::Inventory)
        );
    }
}
