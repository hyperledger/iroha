//! Complete installed wallet verifier inventory and native identity preimages.
//!
//! A pack contains canonical original authority frames and every descriptor/VK of the
//! sixteen sigma selectors plus Omega. Native protocol/profile identities are constructed
//! here from compiled native constants and pinned parameter tables, never from wallet wire
//! inputs. The signed manifest must equal the independently installed manifest digest and
//! the inventory recomputed from the actual mounted bytes.
//!
//! The one signed identity includes the complete producer-catalog commitment; a
//! verifier-only view need not hold that catalog's original proving tables.
//! TODO(G3/G4): qualify every original against its complete Q/A/W/terminal source
//! and connect the native preparation/fold owner. This type grants no wallet-open capability;
//! there is no boolean or argument that upgrades verifier-only admission to producer readiness.

use ff::PrimeField;
use iroha_data_model::kagemusha::kagemusha_wallet_v1::*;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaCurve, params::PARAMS_DOMAIN, poseidon};
use iroha_plonk::{
    DescriptorBinding, Protocol, VerifyingKey,
    cs::{
        CurveV1, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV2,
        descriptor::{PROTOCOL_VERSION, pinned_params_digest},
    },
    keys::VK_VERSION,
    transcript::INSTANCE_FRAME_TAG,
};
use iroha_plonk_recursion::{ACCUMULATOR_BYTES, FOLD_BODY_BYTES, K, transcript::Domain};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
use sha2::{Digest as _, Sha256};

use crate::kagemusha_wallet_proofs_v1::{
    ArtifactSet, Error, LineageArtifact, RuntimeBindings, StepArtifact,
};

/// Non-shipping genuine signed artifact fixtures for native/Core installation tests.
#[cfg(any(test, feature = "test-utils"))]
#[path = "kagemusha_wallet_artifacts_v1/engineering_fixture.rs"]
pub mod engineering_fixture;

/// Authenticated producer inventory and bounded original reads, without source admission.
#[path = "kagemusha_wallet_artifacts_v1/producer_inventory.rs"]
pub mod producer_inventory;

#[cfg(test)]
#[path = "kagemusha_wallet_artifacts_v1/tests.rs"]
mod tests;

/// Complete installed V1 sigma catalog, in global selector order.
/// Receive's mask is the Request-recorded blacklist decision.
pub const SIGMA_CATALOG_V1: [(u8, u32); 16] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (3, 1),
    (3, 2),
    (3, 3),
    (3, 4),
    (3, 5),
    (3, 6),
    (3, 7),
    (4, 0),
    (4, 1),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
];
/// Per-artifact original V2 descriptor cap, before decoding.
pub const DESCRIPTOR_MAX_BYTES_V1: usize = 1 << 20;
/// Per-artifact original native VK cap, before decoding.
pub const VERIFYING_KEY_MAX_BYTES_V1: usize = 1 << 18;
/// Aggregate original descriptor/VK cap across all seventeen artifacts.
pub const INVENTORY_MAX_BYTES_V1: usize = 16 << 20;
/// Complete canonical pack cap including authority frames and codec overhead.
pub const VERIFIER_PACK_MAX_BYTES_V1: usize = INVENTORY_MAX_BYTES_V1 + (1 << 16);

/// Original bytes of one installed descriptor and native verifying key.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.artifact_original.v1")]
pub struct ArtifactOriginalV1 {
    /// Exactly one canonical explicit V2 descriptor.
    pub descriptor: Vec<u8>,
    /// Exactly one native VK bound to that descriptor.
    pub verifying_key: Vec<u8>,
}

/// Selector and original bytes of one installed sigma artifact.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.step_original.v1")]
pub struct StepOriginalV1 {
    /// Operation whose complete step relation this installed key authenticates.
    pub kind: KagemushaWalletOperationKindV1,
    /// Send enabled-controls or Receive Request-recorded blacklist selector.
    pub enabled_controls: u32,
    /// Unmodified descriptor and key originals.
    pub artifact: ArtifactOriginalV1,
}

/// Bounded canonical installation carrier; decoding alone confers no authority.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.verifier_pack.v1")]
pub struct VerifierPackV1 {
    /// Exactly wallet version one.
    pub version: u16,
    /// Original canonical Scheme frame.
    pub scheme: Vec<u8>,
    /// Original canonical Artifact-role signer certificate frame.
    pub signer_certificate: Vec<u8>,
    /// Original canonical signed ArtifactManifest frame.
    pub manifest: Vec<u8>,
    /// Original canonical verifying-key allowlist frame.
    pub allowlist: Vec<u8>,
    /// Every sigma original in the exact full catalog order.
    pub steps: Vec<StepOriginalV1>,
    /// Original Omega descriptor and key.
    pub lineage: ArtifactOriginalV1,
    /// Mandatory commitment to the complete canonical producer inventory.
    /// Verifier-only installation authenticates this commitment without claiming
    /// possession or source qualification of the corresponding proving artifacts.
    pub producer_catalog_digest: [u8; 32],
}

/// Authority provisioned independently by the native installation/configuration.
/// It cannot be taken from a received Payment or foreign wallet-open request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallationV1 {
    /// Exact nonzero scheme identity installed for this wallet runtime.
    pub scheme_id: [u8; 32],
    /// Exact nonzero signed ArtifactManifest digest installed for this runtime.
    pub manifest_digest: [u8; 32],
}

/// Owned, fully authenticated verifier inventory with its original canonical pack.
/// Private construction prevents switching material after admission.
pub struct InstalledVerifierPackV1 {
    original: Vec<u8>,
    pack: VerifierPackV1,
    runtime: RuntimeBindings,
    verifier: ArtifactSet,
}

/// Fixed descriptor policy encoded into the native-profile transcript.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.core_zk.kagemusha.wallet.descriptor_policy.v1")]
struct DescriptorPolicyV1 {
    version: u16,
    curve: CurveV1,
    min_k: u8,
    max_k: u8,
    transcript: TranscriptV2,
    instance_mode: InstanceModeV1,
    proof_suffix: ProofSuffixV1,
    instance_lengths: Vec<u32>,
    instance_types: Vec<InstanceType>,
}

fn policy(lineage: bool) -> DescriptorPolicyV1 {
    DescriptorPolicyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        curve: if lineage {
            CurveV1::Pallas
        } else {
            CurveV1::Vesta
        },
        min_k: if lineage { 16 } else { 12 },
        max_k: 16,
        transcript: TranscriptV2::KagemushaPoseidonRp57Base,
        instance_mode: InstanceModeV1::Direct,
        proof_suffix: ProofSuffixV1::FoldedGenerator,
        instance_lengths: if lineage {
            vec![1, 2, K as u32]
        } else {
            vec![1]
        },
        instance_types: if lineage {
            vec![
                InstanceType::Bounded,
                InstanceType::Field,
                InstanceType::Bounded,
            ]
        } else {
            vec![InstanceType::Bounded]
        },
    }
}

// This uses the wallet's existing H framing for its domain-separated artifact roles.
// Exact role/preimage definitions are in wire §3.1; no relation recomputes these SHA values.
fn artifact_digest(role: &[u8], body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KAGEMUSHA_WALLET_DIGEST_PREFIX_V1);
    h.update(role);
    h.update([0]);
    h.update((body.len() as u64).to_le_bytes());
    h.update(body);
    h.finalize().into()
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| Error::Inventory)?
            .to_le_bytes(),
    );
    Ok(())
}

fn put_frame(bytes: &mut Vec<u8>, frame: &[u8]) -> Result<(), Error> {
    put_u32(bytes, frame.len())?;
    bytes.extend_from_slice(frame);
    Ok(())
}

fn native_protocol_transcript(curve: CurveV1) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&KAGEMUSHA_WALLET_VERSION_V1.to_le_bytes());
    bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    bytes.push(match curve {
        CurveV1::Pallas => 0,
        CurveV1::Vesta => 1,
    });
    bytes.extend_from_slice(&curve.base_modulus());
    bytes.extend_from_slice(&curve.scalar_modulus());
    // V2 schema and personas are frozen by the current explicit native constructors.
    put_frame(&mut bytes, b"iroha.plonk.pipa.circuit_descriptor.v2")?;
    bytes.extend_from_slice(b"PIPA-v2-CircDesc");
    bytes.push(VK_VERSION);
    bytes.extend_from_slice(b"Iroha-PlonkVK-v2");
    bytes.extend_from_slice(b"kgwvkey1");
    bytes.extend_from_slice(&Domain::Proof.tag());
    bytes.extend_from_slice(&Domain::Fold.tag());
    bytes.extend_from_slice(&INSTANCE_FRAME_TAG);
    for value in [
        poseidon::WIDTH,
        poseidon::RATE,
        poseidon::FULL_ROUNDS,
        poseidon::PARTIAL_ROUNDS,
        poseidon::SECURE_MDS,
    ] {
        put_u32(&mut bytes, value)?;
    }
    // Hash the actual pinned native table serialized by its own constructor, not a
    // caller's name/hash or newly generated table.
    let table = match curve {
        CurveV1::Pallas => <Fp as poseidon::PoseidonField>::rp57().to_table(),
        CurveV1::Vesta => <Fq as poseidon::PoseidonField>::rp57().to_table(),
    };
    put_u32(&mut bytes, table.len())?;
    bytes.extend_from_slice(&Sha256::digest(&table));
    put_frame(&mut bytes, PARAMS_DOMAIN.as_bytes())?;
    put_u32(&mut bytes, 5)?;
    for k in 12..=16 {
        bytes.push(k as u8);
        bytes.extend_from_slice(&pinned_params_digest(curve, k).ok_or(Error::Profile)?);
    }
    // Scalar absorption: Pallas low128/high127 pair, Vesta exact Fp integer.
    // Challenge map: Pallas Fp->Fq identity, Vesta Fq->Fp one subtraction.
    bytes.extend_from_slice(match curve {
        CurveV1::Pallas => &[2, 0],
        CurveV1::Vesta => &[1, 1],
    });
    Ok(bytes)
}

/// Exact native Eq protocol preimage, using compiled Vesta/Fq native constructors.
/// # Errors
/// Rejects a missing pinned parameter identity or unrepresentable frame size.
pub fn eq_protocol_transcript_v1() -> Result<Vec<u8>, Error> {
    native_protocol_transcript(CurveV1::Vesta)
}

/// Exact native Ep protocol preimage, using compiled Pallas/Fp native constructors.
/// # Errors
/// Rejects a missing pinned parameter identity or unrepresentable frame size.
pub fn ep_protocol_transcript_v1() -> Result<Vec<u8>, Error> {
    native_protocol_transcript(CurveV1::Pallas)
}

/// Exact sole native artifact-profile preimage; it is not a producer qualification.
/// # Errors
/// Rejects failure to encode the fixed typed descriptor policies.
pub fn native_profile_transcript_v1() -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&KAGEMUSHA_WALLET_VERSION_V1.to_le_bytes());
    put_u32(&mut bytes, SIGMA_CATALOG_V1.len())?;
    for (kind, mask) in SIGMA_CATALOG_V1 {
        bytes.push(kind);
        bytes.extend_from_slice(&mask.to_le_bytes());
    }
    for is_lineage in [false, true] {
        let encoded = norito::encode_canonical(&policy(is_lineage)).map_err(|_| Error::Profile)?;
        put_frame(&mut bytes, &encoded)?;
    }
    for count in [
        KAGEMUSHA_WALLET_CORE_FIELD_ITEMS_V1,
        KAGEMUSHA_WALLET_REST_FIELD_ITEMS_V1,
        KAGEMUSHA_WALLET_STATEMENT_FIELD_ITEMS_V1,
        18,
        52,
        K,
        ACCUMULATOR_BYTES,
        FOLD_BODY_BYTES,
    ] {
        put_u32(&mut bytes, count)?;
    }
    bytes.extend_from_slice(b"kgwomg_1");
    // Mandatory decisions in order: sigma own opening; Omega own opening;
    // transported Pallas claim; transported Vesta claim. These are fixed protocol
    // codes, not caller-provided proof-verdict booleans.
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    put_frame(
        &mut bytes,
        &iroha_kagemusha_proof::a_relation::schedule::compiled::compiled_schedule_transcript()
            .map_err(|_| Error::Profile)?,
    )?;
    put_frame(&mut bytes, &producer_inventory::compiled_sigma_policy()?)?;
    put_frame(
        &mut bytes,
        &iroha_kagemusha_proof::omega::native::compiled_policy_transcript()
            .map_err(|_| Error::Profile)?,
    )?;
    Ok(bytes)
}

fn bounded(bytes: &[u8], max: usize) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(Error::Inventory);
    }
    Ok(())
}

fn artifact_bounds(artifact: &ArtifactOriginalV1, total: &mut usize) -> Result<(), Error> {
    bounded(&artifact.descriptor, DESCRIPTOR_MAX_BYTES_V1)?;
    bounded(&artifact.verifying_key, VERIFYING_KEY_MAX_BYTES_V1)?;
    *total = total
        .checked_add(artifact.descriptor.len())
        .and_then(|n| n.checked_add(artifact.verifying_key.len()))
        .ok_or(Error::Inventory)?;
    if *total > INVENTORY_MAX_BYTES_V1 {
        return Err(Error::Inventory);
    }
    Ok(())
}

fn authority<T>(result: Result<T, KagemushaWalletValidationErrorV1>) -> Result<T, Error> {
    result.map_err(|_| Error::Authority)
}

impl VerifierPackV1 {
    fn inventory_bounds(&self) -> Result<(), Error> {
        if self.version != KAGEMUSHA_WALLET_VERSION_V1
            || self.steps.len() != SIGMA_CATALOG_V1.len()
            || self.producer_catalog_digest == [0; 32]
        {
            return Err(Error::Inventory);
        }
        bounded(
            &self.allowlist,
            KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1,
        )?;
        let mut total = 0;
        for (step, expected) in self.steps.iter().zip(SIGMA_CATALOG_V1) {
            if (step.kind.tag(), step.enabled_controls) != expected {
                return Err(Error::Inventory);
            }
            artifact_bounds(&step.artifact, &mut total)?;
        }
        artifact_bounds(&self.lineage, &mut total)
    }

    fn bounds(&self) -> Result<(), Error> {
        self.inventory_bounds()?;
        bounded(&self.scheme, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1)?;
        bounded(
            &self.signer_certificate,
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        )?;
        bounded(
            &self.manifest,
            KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1,
        )
    }

    /// Encode one bounded canonical installation carrier; this does not authenticate it.
    /// # Errors
    /// Rejects missing/full-catalog deviations, oversized originals or encoding failure.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.bounds()?;
        let bytes = norito::encode_canonical(self).map_err(|_| Error::Inventory)?;
        bounded(&bytes, VERIFIER_PACK_MAX_BYTES_V1)?;
        Ok(bytes)
    }

    /// Decode one exact canonical installation carrier, with limits before allocation.
    /// This never attempts another schema/profile or decodes a compressed archive.
    /// # Errors
    /// Rejects an oversized/noncanonical frame or missing/full-catalog deviations.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Error> {
        bounded(bytes, VERIFIER_PACK_MAX_BYTES_V1)?;
        let limits = norito::canonical_decode_limits(bytes.len());
        let pack: Self =
            norito::decode_canonical_with_limits(bytes, limits).map_err(|_| Error::Inventory)?;
        pack.bounds()?;
        Ok(pack)
    }

    /// Compute actual mounted inventory bindings before the release signer creates its
    /// manifest. Authority frames are intentionally excluded from the inventory to avoid
    /// the circular relation->inventory->manifest/scheme binding. This grants no admission.
    /// # Errors
    /// Rejects incomplete catalogs, wrong native profiles, substituted VKs, noncanonical
    /// originals or an allowlist with a different actual complete key digest/proof length.
    pub fn artifact_inventory_transcript(&self) -> Result<Vec<u8>, Error> {
        self.inventory_bounds()?;
        let allowlist: KagemushaWalletVerifyingKeyAllowlistV1 =
            norito::decode_canonical_with_limits(
                &self.allowlist,
                norito::canonical_decode_limits(self.allowlist.len()),
            )
            .map_err(|_| Error::Inventory)?;
        authority(allowlist.validate())?;
        if allowlist.steps.len() != SIGMA_CATALOG_V1.len() {
            return Err(Error::Inventory);
        }
        let eq_protocol_digest = artifact_digest(b"eq-protocol", &eq_protocol_transcript_v1()?);
        let ep_protocol_digest = artifact_digest(b"ep-protocol", &ep_protocol_transcript_v1()?);
        let native_profile_digest =
            artifact_digest(b"native-profile", &native_profile_transcript_v1()?);
        let mut inventory = Vec::new();
        inventory.extend_from_slice(&self.version.to_le_bytes());
        inventory.extend_from_slice(&eq_protocol_digest);
        inventory.extend_from_slice(&ep_protocol_digest);
        inventory.extend_from_slice(&native_profile_digest);
        put_u32(&mut inventory, self.allowlist.len())?;
        inventory.extend_from_slice(&Sha256::digest(&self.allowlist));
        put_u32(&mut inventory, SIGMA_CATALOG_V1.len() + 1)?;
        for (step, entry) in self.steps.iter().zip(&allowlist.steps) {
            if (step.kind.tag(), step.enabled_controls) != entry.selector() {
                return Err(Error::Inventory);
            }
            let item = parse_artifact::<Eq>(&step.artifact, false)?;
            if item.verifying_key_digest != entry.verifying_key_digest
                || item.proof_bytes != entry.proof_bytes
            {
                return Err(Error::Profile);
            }
            inventory.push(1);
            inventory.push(step.kind.tag());
            inventory.extend_from_slice(&step.enabled_controls.to_le_bytes());
            item.append(&mut inventory)?;
        }
        let omega = parse_artifact::<Ep>(&self.lineage, true)?;
        if omega.verifying_key_digest != allowlist.lineage_verifying_key_digest
            || omega.proof_bytes != allowlist.lineage_proof_bytes
        {
            return Err(Error::Profile);
        }
        inventory.extend_from_slice(&[2, 0]);
        inventory.extend_from_slice(&0_u32.to_le_bytes());
        omega.append(&mut inventory)?;
        inventory.extend_from_slice(&self.producer_catalog_digest);
        Ok(inventory)
    }

    /// Recompute all four native bindings from the fixed runtime and actual originals.
    /// This is a packaging operation, not authenticated verifier or monetary admission.
    /// # Errors
    /// Rejects every inventory/native-profile/complete-key mismatch described by
    /// [`Self::artifact_inventory_transcript`].
    pub fn runtime_bindings(&self) -> Result<RuntimeBindings, Error> {
        Ok(RuntimeBindings {
            eq_protocol_digest: artifact_digest(b"eq-protocol", &eq_protocol_transcript_v1()?),
            ep_protocol_digest: artifact_digest(b"ep-protocol", &ep_protocol_transcript_v1()?),
            native_profile_digest: artifact_digest(
                b"native-profile",
                &native_profile_transcript_v1()?,
            ),
            artifact_inventory_digest: artifact_digest(
                b"artifact-inventory",
                &self.artifact_inventory_transcript()?,
            ),
        })
    }
}

struct ParsedArtifact {
    curve: CurveV1,
    k: u8,
    descriptor_bytes: usize,
    descriptor_sha256: [u8; 32],
    verifying_key_bytes: usize,
    verifying_key_sha256: [u8; 32],
    descriptor_digest: [u8; 32],
    verifying_key_digest: [u8; 32],
    proof_bytes: u32,
}

impl ParsedArtifact {
    fn append(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        bytes.push(match self.curve {
            CurveV1::Pallas => 0,
            CurveV1::Vesta => 1,
        });
        bytes.push(self.k);
        put_u32(bytes, self.descriptor_bytes)?;
        bytes.extend_from_slice(&self.descriptor_sha256);
        put_u32(bytes, self.verifying_key_bytes)?;
        bytes.extend_from_slice(&self.verifying_key_sha256);
        bytes.extend_from_slice(&self.descriptor_digest);
        bytes.extend_from_slice(&self.verifying_key_digest);
        bytes.extend_from_slice(&self.proof_bytes.to_le_bytes());
        Ok(())
    }
}

fn parse_artifact<C: PastaCurve>(
    original: &ArtifactOriginalV1,
    lineage: bool,
) -> Result<ParsedArtifact, Error> {
    let mut total = 0;
    artifact_bounds(original, &mut total)?;
    let binding = DescriptorBinding::decode_v2(&original.descriptor).map_err(|_| Error::Profile)?;
    let d = binding.descriptor();
    let expected = policy(lineage);
    if d.protocol_version != PROTOCOL_VERSION
        || d.curve != expected.curve
        || !(expected.min_k..=expected.max_k).contains(&d.k)
        || d.transcript != expected.transcript
        || d.instance_mode != expected.instance_mode
        || d.proof_suffix != expected.proof_suffix
        || d.instance_lengths != expected.instance_lengths
        || d.instance_types.as_ref() != Some(&expected.instance_types)
    {
        return Err(Error::Profile);
    }
    let vk =
        VerifyingKey::<C>::read(&original.verifying_key, &binding).map_err(|_| Error::Profile)?;
    let digest = vk
        .kagemusha_digest(&binding)
        .map_err(|_| Error::Profile)?
        .to_repr();
    let length = Protocol::new(d).map_err(|_| Error::Profile)?.proof_length();
    let length = if lineage {
        length
            .checked_add(2 * ACCUMULATOR_BYTES)
            .ok_or(Error::Profile)?
    } else {
        length
    };
    Ok(ParsedArtifact {
        curve: d.curve,
        k: d.k,
        descriptor_bytes: original.descriptor.len(),
        descriptor_sha256: Sha256::digest(&original.descriptor).into(),
        verifying_key_bytes: original.verifying_key.len(),
        verifying_key_sha256: Sha256::digest(&original.verifying_key).into(),
        descriptor_digest: *binding.digest(),
        verifying_key_digest: digest,
        proof_bytes: u32::try_from(length).map_err(|_| Error::Profile)?,
    })
}

impl InstalledVerifierPackV1 {
    /// Admit the actual complete mounted pack against independently provisioned authority.
    /// The manifest cannot choose protocol/profile digests; every binding is recomputed.
    /// # Errors
    /// Rejects all canonical, inventory, native-profile, original-key, signature, scheme,
    /// manifest-identity or exact-proof-length mismatches before returning a verifier.
    pub fn load(original: &[u8], installation: InstallationV1) -> Result<Self, Error> {
        if installation.scheme_id == [0; 32] || installation.manifest_digest == [0; 32] {
            return Err(Error::RuntimeBinding);
        }
        let pack = VerifierPackV1::decode_canonical(original)?;
        let scheme = authority(KagemushaWalletSchemeV1::decode_canonical(
            &pack.scheme,
            &installation.scheme_id,
        ))?;
        if scheme.scheme_id() != installation.scheme_id {
            return Err(Error::RuntimeBinding);
        }
        let signer = authority(KagemushaWalletSignerCertificateV1::decode_canonical(
            &pack.signer_certificate,
            &scheme,
        ))?;
        let manifest = authority(KagemushaWalletArtifactManifestV1::decode_canonical(
            &pack.manifest,
            &scheme,
        ))?;
        authority(manifest.verify(&scheme, &signer))?;
        if manifest.manifest_digest() != installation.manifest_digest {
            return Err(Error::RuntimeBinding);
        }
        let allowlist = authority(KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(
            &pack.allowlist,
            &manifest.body,
        ))?;
        let runtime = pack.runtime_bindings()?;
        let steps: Vec<_> = pack
            .steps
            .iter()
            .map(|s| StepArtifact {
                kind: s.kind,
                enabled_controls: s.enabled_controls,
                descriptor: &s.artifact.descriptor,
                verifying_key: &s.artifact.verifying_key,
            })
            .collect();
        let verifier = ArtifactSet::authenticate(
            scheme,
            &signer,
            &manifest,
            installation.manifest_digest,
            runtime,
            allowlist,
            &steps,
            LineageArtifact {
                descriptor: &pack.lineage.descriptor,
                verifying_key: &pack.lineage.verifying_key,
            },
        )?;
        Ok(Self {
            original: original.to_vec(),
            pack,
            runtime,
            verifier,
        })
    }

    /// Authenticated verifier owner; complete native producer admission remains separate.
    #[must_use]
    pub const fn verifier(&self) -> &ArtifactSet {
        &self.verifier
    }
    /// Exact retained installation frame, for immutable custody/reinstallation comparisons.
    #[must_use]
    pub fn original(&self) -> &[u8] {
        &self.original
    }
    /// Actual mounted original descriptors, keys and authority frames.
    #[must_use]
    pub const fn originals(&self) -> &VerifierPackV1 {
        &self.pack
    }
    /// Recomputed native protocol/profile/inventory identities.
    #[must_use]
    pub const fn runtime_bindings(&self) -> RuntimeBindings {
        self.runtime
    }
}
