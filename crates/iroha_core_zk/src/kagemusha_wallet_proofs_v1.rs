//! Signed wallet artifact admission and native PIPA-R proof verification.
//!
//! This owner accepts explicit V2 descriptors only, binds every key and exact proof length
//! to the scheme's Artifact-role signed manifest, and decides all three obligations of a
//! transported Omega: its own opening and both transported Pasta accumulators. It accepts
//! no foreign proof verdict, alternate decoder or witness-selected runtime profile.
//!
//! Proof verification is one part of monetary admission. The transition owner must also
//! authenticate consumed credentials/objects and compare actual state, map openings and
//! effects before Advance. The installed native state owner connects preparation and the
//! qualified operation/fold source catalog; wallet open requires that complete source grant.
//! This verifier alone grants neither wallet admission nor catalog qualification.

use std::{collections::BTreeMap, sync::Arc};

use ff::PrimeField;
use iroha_data_model::kagemusha::kagemusha_wallet_v1::*;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, PastaCurve, msm::MemoryBudget};
use iroha_plonk::{
    DescriptorBinding, Protocol, VerifyingKey,
    cs::{CurveV1, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV2},
    pcs::ipa::PinnedParams,
    verifier::verify_full_cancellable,
};
use iroha_plonk_recursion::{ACCUMULATOR_BYTES, AccumulatorT, K};

mod cancellation;
pub(crate) mod randomness;
pub(crate) use cancellation::NativeProofError;

/// Native artifact/proof admission failure. No failure selects or modifies wallet state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A signed scheme, certificate, manifest or canonical wallet object is invalid.
    #[error("invalid wallet authority or object")]
    Authority,
    /// Artifact binding differs from the independently installed native runtime.
    #[error("wallet artifact runtime binding differs")]
    RuntimeBinding,
    /// Missing, duplicate, out-of-order or oversized artifact material.
    #[error("invalid wallet artifact inventory")]
    Inventory,
    /// Reinstallable artifact storage is absent or temporarily unreadable.
    /// This is neither proof rejection nor loss of monetary custody.
    #[error("wallet proof artifacts unavailable")]
    Unavailable,
    /// Descriptor, key, curve, instance types, parameters or proof layout differ.
    #[error("invalid wallet proof artifact profile")]
    Profile,
    /// The caller cancelled proof work; no invalid-proof verdict or monetary effect follows.
    #[error("wallet proof work cancelled")]
    Cancelled,
    /// Canonical transport, proof equation or complete accumulator decide failed.
    #[error("wallet proof rejected")]
    Proof,
}

impl Error {
    /// Whether a caller cancelled this operation rather than receiving a proof verdict.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

fn verification_error(error: iroha_plonk::VerifyError) -> Error {
    if error.is_cancelled() {
        Error::Cancelled
    } else {
        Error::Proof
    }
}

fn recursion_error(error: iroha_plonk_recursion::Error) -> Error {
    if error.is_cancelled() {
        Error::Cancelled
    } else {
        Error::Proof
    }
}

/// Independently installed native bindings; never read these from a Payment or foreign open.
///
/// The artifact owner obtains these from its frozen native package/configuration. Requiring
/// the signed manifest to carry them does not require release-review/sign-off receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeBindings {
    /// Installed Eq protocol identity.
    pub eq_protocol_digest: [u8; 32],
    /// Installed Ep protocol identity.
    pub ep_protocol_digest: [u8; 32],
    /// Installed native operation/prover profile.
    pub native_profile_digest: [u8; 32],
    /// Digest of the actual installed complete artifact inventory.
    pub artifact_inventory_digest: [u8; 32],
}

impl RuntimeBindings {
    fn require(&self, manifest: &KagemushaWalletArtifactManifestV1) -> Result<(), Error> {
        let body = &manifest.body;
        for (expected, actual) in [
            (self.eq_protocol_digest, body.eq_protocol_digest),
            (self.ep_protocol_digest, body.ep_protocol_digest),
            (self.native_profile_digest, body.native_profile_digest),
            (
                self.artifact_inventory_digest,
                body.artifact_inventory_digest,
            ),
        ] {
            if expected == [0; 32] || expected != actual {
                return Err(Error::RuntimeBinding);
            }
        }
        Ok(())
    }
}

/// Original descriptor and verifying-key bytes of one sigma artifact.
pub struct StepArtifact<'a> {
    /// Exact allowlist operation tag.
    pub kind: KagemushaWalletOperationKindV1,
    /// Send control mask or Request-recorded Receive blacklist selector.
    pub enabled_controls: u32,
    /// Canonical V2 descriptor.
    pub descriptor: &'a [u8],
    /// Canonical native verifying key.
    pub verifying_key: &'a [u8],
}

/// Original descriptor and verifying-key bytes of the one Omega transport artifact.
pub struct LineageArtifact<'a> {
    /// Canonical V2 descriptor.
    pub descriptor: &'a [u8],
    /// Canonical native verifying key.
    pub verifying_key: &'a [u8],
}

struct Key<C: PastaCurve> {
    binding: DescriptorBinding,
    vk: VerifyingKey<C>,
    params: Arc<PinnedParams<C>>,
    proof_bytes: usize,
}

fn authority<T>(value: Result<T, KagemushaWalletValidationErrorV1>) -> Result<T, Error> {
    value.map_err(|_| Error::Authority)
}

fn binding(descriptor: &[u8], curve: CurveV1, lineage: bool) -> Result<DescriptorBinding, Error> {
    let binding = DescriptorBinding::decode_v2(descriptor).map_err(|_| Error::Profile)?;
    let d = binding.descriptor();
    let (lengths, types): (&[u32], &[InstanceType]) = if lineage {
        (
            &[1, 2, K as u32],
            &[
                InstanceType::Bounded,
                InstanceType::Field,
                InstanceType::Bounded,
            ],
        )
    } else {
        (&[1], &[InstanceType::Bounded])
    };
    if d.curve != curve
        || !(12..=16).contains(&d.k)
        || (lineage && d.k != 16)
        || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
        || d.instance_mode != InstanceModeV1::Direct
        || d.proof_suffix != ProofSuffixV1::FoldedGenerator
        || d.instance_lengths != lengths
        || d.instance_types.as_deref() != Some(types)
    {
        return Err(Error::Profile);
    }
    Ok(binding)
}

// Bound untrusted bytes before descriptor/key decoding or parameter derivation. These are
// loader resource limits, not evidence of physical-phone memory qualification.
const DESCRIPTOR_MAX: usize = 1 << 20;
const KEY_MAX: usize = 1 << 18;
const INVENTORY_MAX: usize = 16 << 20;

fn inventory_size<'a>(items: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Result<(), Error> {
    let mut total = 0_usize;
    for (descriptor, key) in items {
        if descriptor.is_empty()
            || descriptor.len() > DESCRIPTOR_MAX
            || key.is_empty()
            || key.len() > KEY_MAX
        {
            return Err(Error::Inventory);
        }
        total = total
            .checked_add(descriptor.len())
            .and_then(|v| v.checked_add(key.len()))
            .ok_or(Error::Inventory)?;
        if total > INVENTORY_MAX {
            return Err(Error::Inventory);
        }
    }
    Ok(())
}

// Each required Request is one exact retained original, never an independently supplied
// selector DTO. A second matching role is ambiguous even when its bytes happen to agree.
fn retained_request(
    capsule: &KagemushaWalletRecoveryCapsuleV1,
) -> Result<KagemushaWalletRequestV1, Error> {
    let mut originals = capsule
        .retained_inputs
        .iter()
        .filter(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request);
    let original = originals.next().ok_or(Error::Authority)?;
    if originals.next().is_some()
        || original.bytes.is_empty()
        || original.bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
    {
        return Err(Error::Authority);
    }
    norito::decode_canonical_with_limits(
        &original.bytes,
        norito::canonical_decode_limits(original.bytes.len()),
    )
    .map_err(|_| Error::Authority)
}

// Proof-context checks are not a NativeProofs implementation. In particular, they never
// turn a retained incoming Payment's soft validity into a hard acceptance prerequisite.
fn capsule_selector(
    scheme: &KagemushaWalletSchemeV1,
    capsule: &KagemushaWalletRecoveryCapsuleV1,
    credential: &KagemushaWalletCredentialV1,
) -> Result<(KagemushaWalletOperationKindV1, u32), Error> {
    authority(capsule.to_canonical_bytes())?;
    authority(credential.validate())?;
    authority(capsule.statement.validate_for_scheme(scheme))?;
    authority(capsule.statement.validate_for_credential(credential))?;
    authority(capsule.successor_state.validate_for_credential(credential))?;
    let owner = &credential.body;
    let kind = capsule.kind;
    match capsule.statement.effect {
        KagemushaWalletEffectV1::Send {
            credit_id,
            receiver_wallet_id,
            send_ordinal,
            amount,
            fee,
            request: request_digest,
            accepted_lower_ms,
            ..
        } => {
            let request = retained_request(capsule)?;
            authority(request.verify(scheme))?;
            let body = &request.body;
            if body.payer_wallet_id != owner.wallet_id
                || body.payer_account_digest != owner.account_digest
                || body.asset_digest != owner.asset_digest
                || request.receiver_credential.body.payment_key == owner.payment_key
                || body.credit_id() != credit_id
                || body.receiver_wallet_id != receiver_wallet_id
                || body.send_ordinal != send_ordinal
                || body.amount != amount
                || body.fee != fee
                || request.request_digest() != request_digest
                || accepted_lower_ms < body.receiver_accepted_time_ms
            {
                return Err(Error::Authority);
            }
            Ok((kind, capsule.statement.enabled_controls))
        }
        KagemushaWalletEffectV1::Receive {
            credit_id,
            payer_wallet_id,
            amount,
        } => {
            let request = retained_request(capsule)?;
            authority(request.verify(scheme))?;
            let body = &request.body;
            if body.receiver_wallet_id != owner.wallet_id
                || body.receiver_account_digest != owner.account_digest
                || body.asset_digest != owner.asset_digest
                || request.receiver_credential.body.payment_key != owner.payment_key
                || body.credit_id() != credit_id
                || body.payer_wallet_id != payer_wallet_id
                || body.amount != amount
            {
                return Err(Error::Authority);
            }
            // The quoted credential may precede a renewal. Stable wallet/account/asset/key
            // bindings above apply; current credential-digest equality would strand it.
            let mask = if body.receiver_blacklist_version == 0 {
                0
            } else {
                KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1
            };
            Ok((kind, mask))
        }
        _ => Ok((kind, 0)),
    }
}

/// Complete authenticated sigma/transport verifier set for one installed scheme.
///
/// Private fields prevent a caller from constructing an authenticated set from its own
/// success boolean or swapping a key after admission. Proving-stage artifacts and their
/// complete schedule remain owned by the native operation prover.
pub struct ArtifactSet {
    scheme: KagemushaWalletSchemeV1,
    manifest_digest: [u8; 32],
    allowlist: KagemushaWalletVerifyingKeyAllowlistV1,
    steps: BTreeMap<(u8, u32), Key<Eq>>,
    lineage: Key<Ep>,
    vesta: Arc<PinnedParams<Eq>>,
}

impl ArtifactSet {
    /// Authenticate the installed scheme, role certificate, manifest and complete key set.
    ///
    /// `expected_manifest` and `runtime` come from the native installation, not a wire
    /// object. Parameter sets use the transparent native derivation and are shared by k.
    /// All selectors must be present in exact allowlist order; extras and partial imports
    /// are rejected. The descriptor-derived Omega length includes both 544-byte claims.
    ///
    /// # Errors
    /// Reject mismatching authority/bindings, missing or oversized artifacts, non-V2 or
    /// wrong-profile descriptors, substituted keys and any exact-proof-length mismatch.
    pub fn authenticate(
        scheme: KagemushaWalletSchemeV1,
        signer: &KagemushaWalletSignerCertificateV1,
        manifest: &KagemushaWalletArtifactManifestV1,
        expected_manifest: [u8; 32],
        runtime: RuntimeBindings,
        allowlist: KagemushaWalletVerifyingKeyAllowlistV1,
        steps: &[StepArtifact<'_>],
        lineage: LineageArtifact<'_>,
    ) -> Result<Self, Error> {
        authority(scheme.validate())?;
        authority(manifest.verify(&scheme, signer))?;
        if expected_manifest == [0; 32] || manifest.manifest_digest() != expected_manifest {
            return Err(Error::RuntimeBinding);
        }
        runtime.require(manifest)?;
        authority(allowlist.require_manifest(&manifest.body))?;
        if steps.len() != allowlist.steps.len() {
            return Err(Error::Inventory);
        }
        inventory_size(
            steps
                .iter()
                .map(|s| (s.descriptor, s.verifying_key))
                .chain([(lineage.descriptor, lineage.verifying_key)]),
        )?;

        // Decode every key and check every signed digest/length before expensive params.
        let mut decoded = Vec::with_capacity(steps.len());
        for (artifact, entry) in steps.iter().zip(&allowlist.steps) {
            if (artifact.kind.tag(), artifact.enabled_controls) != entry.selector() {
                return Err(Error::Inventory);
            }
            let binding = binding(artifact.descriptor, CurveV1::Vesta, false)?;
            let vk = VerifyingKey::<Eq>::read(artifact.verifying_key, &binding)
                .map_err(|_| Error::Profile)?;
            let digest = vk.kagemusha_digest(&binding).map_err(|_| Error::Profile)?;
            let bytes = Protocol::new(binding.descriptor())
                .map_err(|_| Error::Profile)?
                .proof_length();
            if digest.to_repr() != entry.verifying_key_digest
                || u32::try_from(bytes).ok() != Some(entry.proof_bytes)
            {
                return Err(Error::Profile);
            }
            decoded.push((entry.selector(), binding, vk, bytes));
        }
        let omega_binding = binding(lineage.descriptor, CurveV1::Pallas, true)?;
        let omega_vk = VerifyingKey::<Ep>::read(lineage.verifying_key, &omega_binding)
            .map_err(|_| Error::Profile)?;
        let omega_digest = omega_vk
            .kagemusha_digest(&omega_binding)
            .map_err(|_| Error::Profile)?;
        let omega_bytes = Protocol::new(omega_binding.descriptor())
            .map_err(|_| Error::Profile)?
            .proof_length();
        let transport_bytes = omega_bytes
            .checked_add(2 * ACCUMULATOR_BYTES)
            .ok_or(Error::Profile)?;
        if omega_digest.to_repr() != allowlist.lineage_verifying_key_digest
            || u32::try_from(transport_bytes).ok() != Some(allowlist.lineage_proof_bytes)
        {
            return Err(Error::Profile);
        }

        let mut params = BTreeMap::new();
        let mut keys = BTreeMap::new();
        for (selector, binding, vk, proof_bytes) in decoded {
            let k = u32::from(binding.descriptor().k);
            let pinned = match params.get(&k) {
                Some(p) => Arc::clone(p),
                None => {
                    let p = Arc::new(PinnedParams::<Eq>::derive(k).map_err(|_| Error::Profile)?);
                    params.insert(k, Arc::clone(&p));
                    p
                }
            };
            keys.insert(
                selector,
                Key {
                    binding,
                    vk,
                    params: pinned,
                    proof_bytes,
                },
            );
        }
        let vesta = match params.remove(&16) {
            Some(p) => p,
            None => Arc::new(PinnedParams::<Eq>::derive(16).map_err(|_| Error::Profile)?),
        };
        let pallas = Arc::new(PinnedParams::<Ep>::derive(16).map_err(|_| Error::Profile)?);
        Ok(Self {
            scheme,
            manifest_digest: expected_manifest,
            allowlist,
            steps: keys,
            lineage: Key {
                binding: omega_binding,
                vk: omega_vk,
                params: pallas,
                proof_bytes: omega_bytes,
            },
            vesta,
        })
    }

    /// Signed manifest identity of this immutable verifier set.
    #[must_use]
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    /// Installed scheme selected by the native artifact owner.
    #[must_use]
    pub const fn scheme(&self) -> &KagemushaWalletSchemeV1 {
        &self.scheme
    }

    /// Borrow the exact Vesta parameters derived by this installation, without
    /// deriving generators in an active foreground or background operation.
    pub(crate) fn vesta_parameters(&self, k: u32) -> Result<&Arc<PinnedParams<Eq>>, Error> {
        if k == 16 {
            return Ok(&self.vesta);
        }
        self.steps
            .values()
            .find(|key| key.params.params().k() == k)
            .map(|key| &key.params)
            .ok_or(Error::Profile)
    }

    /// Borrow this installation's exact k16 Pallas parameters for Q and Omega.
    pub(crate) const fn pallas_parameters(&self) -> &Arc<PinnedParams<Ep>> {
        &self.lineage.params
    }

    /// Verify a package's sigma and carried Omega using its canonical selector.
    ///
    /// Receive selection requires its exact Request, including the historical blacklist
    /// decision. This method verifies proofs; receipt/current credential/object and actual
    /// state/map checks remain mandatory in the transition owner before monetary mutation.
    ///
    /// # Errors
    /// Invalid package/scheme/selector, wrong exact lengths or failed proof/decide.
    pub fn verify_package_proofs(
        &self,
        package: &KagemushaWalletPackageV1,
        request: Option<&KagemushaWalletRequestBodyV1>,
        budget: MemoryBudget,
    ) -> Result<(), Error> {
        self.verify_package_proofs_cancellable(package, request, budget, None)
    }

    /// Perform the same complete verification with a caller-owned cancellation signal.
    /// # Errors
    /// Preserves verification failures; interruption returns `Cancelled`, never a verdict.
    pub fn verify_package_proofs_cancellable(
        &self,
        package: &KagemushaWalletPackageV1,
        request: Option<&KagemushaWalletRequestBodyV1>,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        authority(package.statement.validate_for_scheme(&self.scheme))?;
        authority(self.allowlist.check_package(package, request))?;
        let (kind, mask) = authority(package.verifying_key_selector(request))?;
        self.verify_step_proof_cancellable(
            &package.statement,
            &package.step_proof,
            kind,
            mask,
            budget,
            cancellation,
        )?;
        if let Some(lineage) = package.lineage.lineage() {
            self.verify_lineage_cancellable(lineage, budget, cancellation)?;
        }
        Ok(())
    }

    /// Verify receipt-free pre-Advance capsule sigma and its required predecessor Omega.
    ///
    /// The immutable installed scheme/allowlist choose every key and exact proof length.
    /// Send and Receive use the unique retained canonical signed Request; Receive selects
    /// its historical blacklist decision and keeps the stable current wallet/account/key
    /// bindings across renewal. No caller supplies a Request body, mask or future Receipt.
    ///
    /// This is proof verification, not operation admission. The Native transition owner
    /// still authenticates the current credential's issuer, all consumed originals, actual
    /// predecessor/state/map effects and Receive's soft incoming validity/burn relation.
    /// The incoming Payment is never hard-decoded here to bypass that separate relation.
    /// This method grants no wallet-open capability or completed fold/producer schedule.
    ///
    /// # Errors
    /// Invalid capsule/current-credential/context, missing/ambiguous/noncanonical Request,
    /// wrong scheme/selector/exact proof length, or failed sigma/Omega/complete decides.
    pub fn verify_capsule_proofs(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        credential: &KagemushaWalletCredentialV1,
        budget: MemoryBudget,
    ) -> Result<(), Error> {
        self.verify_capsule_proofs_cancellable(capsule, credential, budget, None)
    }

    /// Perform the same complete verification with a caller-owned cancellation signal.
    /// # Errors
    /// Preserves verification failures; interruption returns `Cancelled`, never a verdict.
    pub fn verify_capsule_proofs_cancellable(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        credential: &KagemushaWalletCredentialV1,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let (kind, mask) = capsule_selector(&self.scheme, capsule, credential)?;
        self.verify_step_proof_cancellable(
            &capsule.statement,
            &capsule.step_proof,
            kind,
            mask,
            budget,
            cancellation,
        )?;
        if let Some(lineage) = capsule.predecessor_lineage() {
            self.verify_lineage_cancellable(lineage, budget, cancellation)?;
        }
        Ok(())
    }

    // Both receipt-bearing and pre-Advance paths use the same immutable admitted key,
    // canonical statement instance, exact layout and complete native sigma verifier.
    /// Perform the same complete verification with a caller-owned cancellation signal.
    /// # Errors
    /// Preserves verification failures; interruption returns `Cancelled`, never a verdict.
    pub(super) fn verify_step_proof_cancellable(
        &self,
        statement: &KagemushaWalletStatementV1,
        proof: &KagemushaWalletStepProofV1,
        kind: KagemushaWalletOperationKindV1,
        mask: u32,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        authority(statement.validate_for_scheme(&self.scheme))?;
        authority(self.allowlist.check_step_proof(kind, mask, proof))?;
        let key = self.steps.get(&(kind.tag(), mask)).ok_or(Error::Profile)?;
        let digest = authority(statement.statement_digest())?;
        let instance = Option::<Fp>::from(Fp::from_repr(digest)).ok_or(Error::Authority)?;
        if proof.bytes.len() != key.proof_bytes {
            return Err(Error::Proof);
        }
        verify_full_cancellable(
            &key.params,
            &key.binding,
            &key.vk,
            &[vec![instance]],
            &proof.bytes,
            budget,
            cancellation,
        )
        .map_err(verification_error)
    }

    /// Fully verify Omega and all transported accumulator obligations.
    ///
    /// D_A is recomputed from every canonical public field, the original acc_P and the
    /// installed Omega key digest. Neither coordinates, challenges nor public extensions
    /// are accepted as independent caller instances. Both accumulator encodings are exact.
    ///
    /// # Errors
    /// Another scheme/relation, noncanonical/wrong-sized transport, wrong public binding,
    /// failed Omega opening or failed complete Pallas/Vesta decide.
    pub fn verify_lineage(
        &self,
        lineage: &KagemushaWalletLineageV1,
        budget: MemoryBudget,
    ) -> Result<(), Error> {
        self.verify_lineage_cancellable(lineage, budget, None)
    }

    /// Perform the same complete verification with a caller-owned cancellation signal.
    /// # Errors
    /// Preserves verification failures; interruption returns `Cancelled`, never a verdict.
    pub fn verify_lineage_cancellable(
        &self,
        lineage: &KagemushaWalletLineageV1,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        authority(self.allowlist.check_lineage(lineage))?;
        if lineage.public.scheme_id != self.scheme.scheme_id()
            || lineage.public.relation_id != self.scheme.relation_id
        {
            return Err(Error::Authority);
        }
        let (proof, pallas, vesta) = decode_transport(&lineage.proof, self.lineage.proof_bytes)?;
        let digest = lineage_digest(
            &lineage.public,
            self.allowlist.lineage_verifying_key_digest,
            &pallas,
        )?;
        let (x, y) = Option::<(Fq, Fq)>::from(vesta.g().coordinates()).ok_or(Error::Proof)?;
        let mut challenges = Vec::with_capacity(K);
        for value in vesta.challenges() {
            challenges
                .push(Option::<Fq>::from(Fq::from_repr(value.to_repr())).ok_or(Error::Proof)?);
        }
        let instances = [
            vec![Option::<Fq>::from(Fq::from_repr(digest)).ok_or(Error::Proof)?],
            vec![x, y],
            challenges,
        ];
        verify_full_cancellable(
            &self.lineage.params,
            &self.lineage.binding,
            &self.lineage.vk,
            &instances,
            proof,
            budget,
            cancellation,
        )
        .map_err(verification_error)?;
        pallas
            .decide_cancellable(&self.lineage.params, budget, cancellation)
            .map_err(recursion_error)?;
        vesta
            .decide_cancellable(&self.vesta, budget, cancellation)
            .map_err(recursion_error)?;
        Ok(())
    }
}

fn decode_transport(
    bytes: &[u8],
    proof_bytes: usize,
) -> Result<(&[u8], AccumulatorT<Ep>, AccumulatorT<Eq>), Error> {
    if proof_bytes == 0 || proof_bytes.checked_add(2 * ACCUMULATOR_BYTES) != Some(bytes.len()) {
        return Err(Error::Proof);
    }
    let (proof, claims) = bytes.split_at(proof_bytes);
    let (pallas, vesta) = claims.split_at(ACCUMULATOR_BYTES);
    Ok((
        proof,
        AccumulatorT::from_bytes(pallas).map_err(|_| Error::Proof)?,
        AccumulatorT::from_bytes(vesta).map_err(|_| Error::Proof)?,
    ))
}

fn limbs(bytes: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut low = [0; 32];
    let mut high = [0; 32];
    low[..16].copy_from_slice(&bytes[..16]);
    high[..16].copy_from_slice(&bytes[16..]);
    [low, high]
}

/// The exact eighteen-field native Omega public prefix, including its independently
/// installed verifying-key digest. Preparation and D_A verification share this encoding.
/// This conversion supplies a witness only; it does not authenticate or accept a lineage.
pub(crate) fn lineage_public_fields(
    public: &KagemushaWalletLineagePublicV1,
    omega_key_digest: [u8; 32],
) -> Result<[Fp; 18], Error> {
    authority(public.validate())?;
    let mut fields = Vec::with_capacity(18);
    fields.push(Fp::from(u64::from(public.version)).to_repr());
    fields.extend(limbs(&public.scheme_id));
    fields.extend(limbs(&public.relation_id));
    fields.push(public.head.value);
    fields.extend(limbs(&public.wallet_id));
    fields.push(public.credential_digest);
    let key = public.payment_key.as_sec1_bytes();
    // SEC1 coordinates are big-endian; all protocol field limbs are little-endian.
    for coordinate in [&key[1..33], &key[33..65]] {
        let mut bytes = [0; 32];
        for (to, from) in bytes.iter_mut().zip(coordinate.iter().rev()) {
            *to = *from;
        }
        fields.extend(limbs(&bytes));
    }
    let policy = u128::from(public.lifecycle.tag())
        | (u128::from(public.policy_epoch) << 8)
        | (u128::from(public.enabled_controls) << 72);
    fields.push(kagemusha_wallet_field_from_u128_v1(policy));
    fields.push(kagemusha_wallet_field_from_u128_v1(public.burned_total));
    fields.push(public.pending_outgoing_root);
    fields.push(public.credit_digest_root);
    fields.push(omega_key_digest);
    fields
        .into_iter()
        .map(|field| Option::<Fp>::from(Fp::from_repr(field)).ok_or(Error::Authority))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| Error::Authority)
}

fn lineage_digest(
    public: &KagemushaWalletLineagePublicV1,
    omega_key_digest: [u8; 32],
    pallas: &AccumulatorT<Ep>,
) -> Result<[u8; 32], Error> {
    let mut fields = Vec::with_capacity(52);
    fields.extend(lineage_public_fields(public, omega_key_digest)?.map(|field| field.to_repr()));
    let (x, y) = Option::<(Fp, Fp)>::from(pallas.g().coordinates()).ok_or(Error::Proof)?;
    fields.extend([x.to_repr(), y.to_repr()]);
    for challenge in pallas.challenges() {
        fields.extend(limbs(&challenge.to_repr()));
    }
    authority(kagemusha_wallet_poseidon_v1(
        u64::from_le_bytes(*b"kgwomg_1"),
        &fields,
    ))
}

#[cfg(test)]
#[path = "kagemusha_wallet_proofs_v1/tests.rs"]
mod tests;
