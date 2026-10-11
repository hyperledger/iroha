//! Genuine signed complete verifier inventory for non-shipping installation tests.
//!
//! The small circuits test artifact authentication and immutable ledger custody only.
//! They are not wallet monetary relations, a producer catalog or release qualification.

use super::*;
use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Fixed, Instance, Rotation},
    frontend::{Circuit, Error as SynthesisError, Layouter, SimpleFloorPlanner, Value},
    keys::{KeygenConfigV2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

#[derive(Clone)]
struct OriginalCircuit<const LINEAGE: bool> {
    marker: u64,
}

#[derive(Clone, Debug)]
struct Config {
    advice: Column<Advice>,
    marker: Column<Fixed>,
    instances: Vec<Column<Instance>>,
}

impl<F: PastaField, const LINEAGE: bool> Circuit<F> for OriginalCircuit<LINEAGE> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let advice = meta.advice_column();
        let marker = meta.fixed_column();
        meta.enable_equality(advice);
        let lengths = if LINEAGE { vec![1, 2, K] } else { vec![1] };
        let instances = lengths
            .into_iter()
            .map(|length| {
                let column = meta.instance_column(length);
                meta.enable_equality(column);
                column
            })
            .collect();
        meta.create_gate("original marker", |cells| {
            vec![
                cells.query_advice(advice, Rotation::cur())
                    - cells.query_fixed(marker, Rotation::cur()),
            ]
        });
        Config {
            advice,
            marker,
            instances,
        }
    }

    fn synthesize(
        &self,
        config: Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), SynthesisError> {
        let lengths = if LINEAGE { vec![1, 2, K] } else { vec![1] };
        let cells = layouter.assign_region(
            || "original public marker",
            |mut region| {
                let mut cells = Vec::new();
                for row in 0..lengths.iter().sum() {
                    let value = F::from(self.marker + row as u64);
                    region.assign_fixed(config.marker, row, value)?;
                    cells.push(
                        region
                            .assign_advice(config.advice, row, Value::known(value))?
                            .cell(),
                    );
                }
                Ok(cells)
            },
        )?;
        let mut offset = 0;
        for (column, length) in config.instances.iter().zip(lengths) {
            for row in 0..length {
                layouter.constrain_instance(cells[offset], *column, row)?;
                offset += 1;
            }
        }
        Ok(())
    }
}

fn original<C: PastaCurve, const LINEAGE: bool>(
    params: &PinnedParams<C>,
    marker: u64,
) -> ArtifactOriginalV1 {
    let types = if LINEAGE {
        vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ]
    } else {
        vec![InstanceType::Bounded]
    };
    let config = KeygenConfigV2::pipa_r(types);
    let (binding, key) =
        keygen_vk_with_binding_v2(params, &OriginalCircuit::<LINEAGE> { marker }, &config)
            .expect("actual original verifier key generation");
    ArtifactOriginalV1 {
        descriptor: binding.encoded().to_vec(),
        verifying_key: key.to_bytes().to_vec(),
    }
}

fn public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .expect("actual P256 fixture point")
}

fn sign(key: &SigningKey, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: Signature = key.sign(message);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
}

/// Generate genuine native V2 keys and signed authority for all sixteen selectors and Omega.
/// The public fixture root is scalar0x11 repeated; it is never an installed release key.
/// These circuits qualify only the installation/immutable-custody code under test.
#[must_use]
pub fn signed_inventory() -> (VerifierPackV1, InstallationV1) {
    let (pack, installation, _) = signed_inventory_with_catalog(|_| None);
    (pack, installation)
}

/// Sign a test-selected catalog commitment before deriving the engineering scheme.
/// No supplied catalog or dummy producer original gains source qualification.
pub(crate) fn signed_inventory_with_catalog(
    catalog: impl FnOnce(&VerifierPackV1) -> Option<Vec<u8>>,
) -> (VerifierPackV1, InstallationV1, Option<Vec<u8>>) {
    build_inventory(Vec::new(), catalog)
}

/// Replace selected sigma originals before any allowlist or authority derivation.
/// Other selectors and Omega remain explicit non-monetary engineering fixtures.
#[cfg(test)]
pub(crate) fn signed_inventory_with_step_originals(
    steps: Vec<StepOriginalV1>,
) -> (VerifierPackV1, InstallationV1) {
    let (pack, installation, _) = build_inventory(steps, |_| None);
    (pack, installation)
}

/// Sign exact test sources and their producer inventory before identity derivation.
/// The caller still must qualify each source; this grants no production authority.
#[cfg(test)]
pub(crate) fn signed_inventory_with_sources(
    steps: Vec<StepOriginalV1>,
    catalog: impl FnOnce(&VerifierPackV1) -> Option<Vec<u8>>,
) -> (VerifierPackV1, InstallationV1, Option<Vec<u8>>) {
    build_inventory(steps, catalog)
}

fn build_inventory(
    replacements: Vec<StepOriginalV1>,
    catalog: impl FnOnce(&VerifierPackV1) -> Option<Vec<u8>>,
) -> (VerifierPackV1, InstallationV1, Option<Vec<u8>>) {
    let mut selected: [Option<StepOriginalV1>; 16] = core::array::from_fn(|_| None);
    for replacement in replacements {
        let index = SIGMA_CATALOG_V1
            .iter()
            .position(|selector| {
                *selector == (replacement.kind.tag(), replacement.enabled_controls)
            })
            .expect("defined replacement selector");
        assert!(
            selected[index].replace(replacement).is_none(),
            "duplicate replacement selector"
        );
    }
    let eq = PinnedParams::<Eq>::derive(12).expect("actual Vesta params");
    let ep = PinnedParams::<Ep>::derive(16).expect("actual Pallas params");
    let steps: Vec<_> = SIGMA_CATALOG_V1
        .iter()
        .enumerate()
        .map(|(index, (tag, mask))| {
            if let Some(replacement) = selected[index].take() {
                return replacement;
            }
            let kind = *KagemushaWalletOperationKindV1::ALL
                .iter()
                .find(|kind| kind.tag() == *tag)
                .expect("catalog kind");
            StepOriginalV1 {
                kind,
                enabled_controls: *mask,
                artifact: original::<Eq, false>(&eq, index as u64 + 1),
            }
        })
        .collect();
    let lineage = original::<Ep, true>(&ep, 100);
    let omega = parse_artifact::<Ep>(&lineage, true).expect("actual Omega profile");
    let allowlist = KagemushaWalletVerifyingKeyAllowlistV1 {
        version: 1,
        steps: steps
            .iter()
            .map(|step| {
                let parsed =
                    parse_artifact::<Eq>(&step.artifact, false).expect("actual sigma profile");
                KagemushaWalletVerifyingKeyEntryV1 {
                    kind: step.kind,
                    enabled_controls: step.enabled_controls,
                    verifying_key_digest: parsed.verifying_key_digest,
                    proof_bytes: parsed.proof_bytes,
                }
            })
            .collect(),
        lineage_verifying_key_digest: omega.verifying_key_digest,
        lineage_proof_bytes: omega.proof_bytes,
    };
    let mut pack = VerifierPackV1 {
        version: 1,
        scheme: Vec::new(),
        signer_certificate: Vec::new(),
        manifest: Vec::new(),
        allowlist: norito::encode_canonical(&allowlist).expect("canonical complete allowlist"),
        steps,
        lineage,
        // This verifier-only engineering inventory deliberately has no producer
        // preimage. Its commitment must never grant source or wallet admission.
        producer_catalog_digest: artifact_digest(b"producer-catalog", b"engineering-verifier-only"),
    };
    let producer = catalog(&pack);
    if let Some(bytes) = &producer {
        pack.producer_catalog_digest = artifact_digest(b"producer-catalog", bytes);
    }
    let runtime = pack
        .runtime_bindings()
        .expect("actual complete native inventory");
    let root = SigningKey::from_bytes((&[0x11; 32]).into()).expect("public fixture root");
    let artifact = SigningKey::from_bytes((&[0x18; 32]).into()).expect("public fixture signer");
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: [0x51; 32],
        scheme_root_key: public(&root),
        relation_id: kagemusha_wallet_relation_id_v1(
            &runtime.eq_protocol_digest,
            &runtime.ep_protocol_digest,
            &runtime.native_profile_digest,
            &allowlist
                .verifying_key_set_digest()
                .expect("actual key set"),
            &runtime.artifact_inventory_digest,
        ),
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let certificate = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Artifact,
        key: public(&artifact),
        serial: 1,
    };
    let signer = KagemushaWalletSignerCertificateV1::sign(
        certificate,
        &scheme,
        sign(&root, &certificate.signing_message()),
    )
    .expect("genuine root certificate signature");
    let body = KagemushaWalletArtifactManifestBodyV1 {
        version: 1,
        network_id: scheme.network_id,
        relation_id: scheme.relation_id,
        eq_protocol_digest: runtime.eq_protocol_digest,
        ep_protocol_digest: runtime.ep_protocol_digest,
        native_profile_digest: runtime.native_profile_digest,
        verifying_key_set_digest: allowlist
            .verifying_key_set_digest()
            .expect("actual key set"),
        artifact_inventory_digest: runtime.artifact_inventory_digest,
        provider_contract: scheme.provider_contract,
        signer_certificate: signer.certificate_digest(),
    };
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        body,
        &signer,
        sign(&artifact, &body.signing_message()),
    )
    .expect("genuine artifact signature");
    pack.scheme = scheme.to_canonical_bytes().expect("canonical scheme");
    pack.signer_certificate = signer.to_canonical_bytes().expect("canonical certificate");
    pack.manifest = manifest.to_canonical_bytes().expect("canonical manifest");
    (
        pack,
        InstallationV1 {
            scheme_id: scheme.scheme_id(),
            manifest_digest: manifest.manifest_digest(),
        },
        producer,
    )
}

/// Sign a different, otherwise valid authority original for the same engineering scheme.
/// This tests immutable installation refusal after authentic native admission succeeds.
#[must_use]
pub fn alternate_authority(
    pack: &VerifierPackV1,
    installation: InstallationV1,
) -> (VerifierPackV1, InstallationV1) {
    let mut changed = pack.clone();
    let scheme = KagemushaWalletSchemeV1::decode_canonical(&pack.scheme, &installation.scheme_id)
        .expect("retained engineering scheme");
    let root = SigningKey::from_bytes((&[0x11; 32]).into()).expect("public fixture root");
    let artifact = SigningKey::from_bytes((&[0x18; 32]).into()).expect("public fixture signer");
    let certificate = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Artifact,
        key: public(&artifact),
        serial: 2,
    };
    let signer = KagemushaWalletSignerCertificateV1::sign(
        certificate,
        &scheme,
        sign(&root, &certificate.signing_message()),
    )
    .expect("alternate genuine certificate");
    let mut body = KagemushaWalletArtifactManifestV1::decode_canonical(&pack.manifest, &scheme)
        .expect("retained engineering manifest")
        .body;
    body.signer_certificate = signer.certificate_digest();
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        body,
        &signer,
        sign(&artifact, &body.signing_message()),
    )
    .expect("alternate genuine manifest");
    changed.signer_certificate = signer.to_canonical_bytes().expect("canonical certificate");
    changed.manifest = manifest.to_canonical_bytes().expect("canonical manifest");
    (
        changed,
        InstallationV1 {
            scheme_id: installation.scheme_id,
            manifest_digest: manifest.manifest_digest(),
        },
    )
}
