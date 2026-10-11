//! Exact built-in native PIPA-R dispatch and canonical Norito proof framing.
//!
//! A registered key must equal the locally compiled key before verification.
//! The proof engine establishes its circuit relation; active registry state,
//! ledger context, permissions and replay protection remain the caller's job.

use ff::PrimeField;
use iroha_data_model::{
    proof::{ProofBox, VerifyingKeyBox},
    zk::{BackendTag, NativePipaRProofV1, OpenVerifyEnvelope},
};
use kaigi_zk::{
    Scalar,
    authorization_v1::{
        KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1, KaigiAuthorizationContextV1,
        KaigiAuthorizationWitnessV1,
    },
    native::{NativeProofV1, NativeRelationV1 as KaigiRelation},
    usage_v1::{KAIGI_USAGE_PUBLIC_INPUTS_SCHEMA_V1, KaigiUsageContextV1},
};
use std::sync::OnceLock;

/// Exact registry label for the built-in native PIPA-R verifier family.
pub const BACKEND: &str = "pipa-r/pasta";
/// Whole-container key bound applied before any expensive material construction.
pub const MAX_KEY_BYTES: usize = 64 * 1024;

/// Canonical registry identity of a built-in native verifier.
///
/// Processed key bytes alone do not bind the transcript or typed public schema.
/// Both exact compiled components are committed by the outer key hash; arbitrary
/// descriptors are never loaded or executed from this carrier.
#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::native_pipa_r::CompiledVerifyingKeyV1")]
pub struct CompiledVerifyingKeyV1 {
    /// Canonical native descriptor bytes, including pinned parameter identity.
    pub descriptor: Vec<u8>,
    /// Processed native key bytes for that exact descriptor.
    pub key: Vec<u8>,
}

fn kaigi_compiled_key(kind: KaigiRelation) -> Result<&'static [u8], String> {
    static AUTHORIZATION: OnceLock<Result<Vec<u8>, String>> = OnceLock::new();
    static USAGE: OnceLock<Result<Vec<u8>, String>> = OnceLock::new();
    let cache = match kind {
        KaigiRelation::Authorization => &AUTHORIZATION,
        KaigiRelation::Usage => &USAGE,
    };
    cache
        .get_or_init(|| {
            let verifier = kind.verifier()?;
            let bytes = norito::encode_canonical(&CompiledVerifyingKeyV1 {
                descriptor: verifier.descriptor_bytes().to_vec(),
                key: verifier.key_bytes().to_vec(),
            })
            .map_err(|error| error.to_string())?;
            if bytes.len() > MAX_KEY_BYTES {
                return Err("compiled native key exceeds registry bound".into());
            }
            Ok(bytes)
        })
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

/// Closed set of compiled native first-release relations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRelationV1 {
    /// Authenticated Kaigi membership and operation authorization.
    KaigiAuthorization,
    /// Host-bound Kaigi usage accounting.
    KaigiUsage,
    /// Two-input/two-output confidential transfer with Merkle membership.
    ConfidentialTransfer,
    /// Confidential redemption of all authenticated input value.
    ConfidentialFullUnshield,
    /// Confidential redemption with optional sender-owned change.
    ConfidentialChangeUnshield,
}
impl From<KaigiRelation> for NativeRelationV1 {
    fn from(kind: KaigiRelation) -> Self {
        match kind {
            KaigiRelation::Authorization => Self::KaigiAuthorization,
            KaigiRelation::Usage => Self::KaigiUsage,
        }
    }
}
impl NativeRelationV1 {
    const ALL: [Self; 5] = [
        Self::KaigiAuthorization,
        Self::KaigiUsage,
        Self::ConfidentialTransfer,
        Self::ConfidentialFullUnshield,
        Self::ConfidentialChangeUnshield,
    ];
    fn kaigi(self) -> Option<KaigiRelation> {
        match self {
            Self::KaigiAuthorization => Some(KaigiRelation::Authorization),
            Self::KaigiUsage => Some(KaigiRelation::Usage),
            _ => None,
        }
    }
    fn confidential(self) -> Option<crate::confidential_v2::native::Kind> {
        use crate::confidential_v2::native::Kind;
        match self {
            Self::ConfidentialTransfer => Some(Kind::Transfer),
            Self::ConfidentialFullUnshield => Some(Kind::Full),
            Self::ConfidentialChangeUnshield => Some(Kind::Change),
            _ => None,
        }
    }
    /// Pinned domain exponent of this exact relation.
    pub const fn k(self) -> u32 {
        if matches!(self, Self::KaigiUsage) {
            12
        } else {
            13
        }
    }
    /// Exact single public-column length.
    pub fn instance_rows(self) -> usize {
        if let Some(kind) = self.kaigi() {
            kind.instance_rows()
        } else {
            self.confidential().expect("closed relation").rows()
        }
    }
    /// Exact circuit identity; no alias normalization is performed.
    pub fn circuit_id(self) -> &'static str {
        if let Some(kind) = self.kaigi() {
            kind.circuit_id()
        } else {
            self.confidential().expect("closed relation").circuit_id()
        }
    }
    /// Exact proof-body length of this locally compiled descriptor.
    ///
    /// # Errors
    /// Deterministic verifier-key construction failed.
    pub fn proof_length(self) -> Result<usize, String> {
        if let Some(kind) = self.kaigi() {
            Ok(kind.verifier()?.proof_length())
        } else {
            crate::confidential_v2::native::proof_length(
                self.confidential().expect("closed relation"),
            )
        }
    }
    fn verify(self, public: &[[u8; 32]], proof: &[u8]) -> Result<(), String> {
        if let Some(kind) = self.kaigi() {
            kind.verifier()?.verify(public, proof)
        } else {
            crate::confidential_v2::native::verify(
                self.confidential().expect("closed relation"),
                public,
                proof,
            )
        }
    }
}
fn compiled_key(kind: NativeRelationV1) -> Result<&'static [u8], String> {
    if let Some(kind) = kind.kaigi() {
        kaigi_compiled_key(kind)
    } else {
        crate::confidential_v2::native::key_bytes(kind.confidential().expect("closed relation"))
    }
}
/// Resolve only an exact generic or relation-specific native backend label.
#[must_use]
pub fn relation(backend: &str, circuit_id: &str) -> Option<NativeRelationV1> {
    NativeRelationV1::ALL.into_iter().find(|kind| {
        circuit_id == kind.circuit_id() && (backend == BACKEND || backend == circuit_id)
    })
}
/// Exact application schema bound by the compiled native relation.
#[must_use]
pub fn public_schema(kind: NativeRelationV1) -> &'static [u8] {
    match kind {
        NativeRelationV1::KaigiAuthorization => KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1,
        NativeRelationV1::KaigiUsage => KAIGI_USAGE_PUBLIC_INPUTS_SCHEMA_V1,
        _ => kind.confidential().expect("closed relation").schema(),
    }
}
/// Reject foreign circuit metadata before native key or proof work.
///
/// # Errors
/// Wrong engine, circuit/backend pair, auxiliary bytes or schema.
pub fn validate_metadata(
    backend: &str,
    envelope: &OpenVerifyEnvelope,
) -> Result<NativeRelationV1, String> {
    if envelope.backend != BackendTag::NativePipaRPasta || !envelope.aux.is_empty() {
        return Err("invalid native PIPA-R envelope metadata".into());
    }
    let kind = relation(backend, &envelope.circuit_id)
        .ok_or_else(|| "unadmitted native PIPA-R circuit/backend pair".to_owned())?;
    if envelope.public_inputs.as_slice() != public_schema(kind) {
        return Err("noncanonical native PIPA-R public-input schema".into());
    }
    Ok(kind)
}
/// Authenticate an exact compiled verifier key; there is no alternate key decoder.
///
/// # Errors
/// Backend/circuit mismatch, oversized container or foreign compiled key bytes.
pub fn validate_key(
    backend: &str,
    circuit: &str,
    key: &VerifyingKeyBox,
) -> Result<NativeRelationV1, String> {
    if key.backend != backend || key.bytes.len() > MAX_KEY_BYTES {
        return Err("invalid native PIPA-R key container".into());
    }
    let kind = relation(backend, circuit)
        .ok_or_else(|| "unadmitted native PIPA-R key relation".to_owned())?;
    if key.bytes != compiled_key(kind)? {
        return Err("native PIPA-R key differs from the compiled relation".into());
    }
    Ok(kind)
}
/// Build the exact native key carrier for a Kaigi relation.
///
/// # Errors
/// Deterministic verifier-only key construction failed.
pub fn kaigi_verifying_key(kind: KaigiRelation) -> Result<VerifyingKeyBox, String> {
    Ok(VerifyingKeyBox::new(
        BACKEND.to_owned(),
        kaigi_compiled_key(kind)?.to_vec(),
    ))
}
fn envelope(kind: KaigiRelation, proved: NativeProofV1) -> Result<OpenVerifyEnvelope, String> {
    let (public_inputs, proof) = proved.into_parts();
    let key = kaigi_verifying_key(kind)?;
    let proof_bytes = norito::encode_canonical(&NativePipaRProofV1 {
        public_inputs,
        proof,
    })
    .map_err(|error| error.to_string())?;
    Ok(OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: kind.circuit_id().to_owned(),
        vk_hash: super::hash_vk(&key),
        public_inputs: public_schema(kind.into()).to_vec(),
        proof_bytes,
        aux: Vec::new(),
    })
}
/// Prove canonical Kaigi authorization and return its self-verified Norito envelope.
///
/// # Errors
/// Invalid context, native proving/verification failure or Norito encoding failure.
pub fn prove_kaigi_authorization(
    context: KaigiAuthorizationContextV1,
    witness: KaigiAuthorizationWitnessV1,
) -> Result<OpenVerifyEnvelope, String> {
    let kind = KaigiRelation::Authorization;
    envelope(kind, kind.prover()?.prove_authorization(context, witness)?)
}
/// Prove host-bound Kaigi usage and return its self-verified Norito envelope.
///
/// # Errors
/// Invalid context, native proving/verification failure or Norito encoding failure.
pub fn prove_kaigi_usage(
    context: KaigiUsageContextV1,
    witness: KaigiAuthorizationWitnessV1,
) -> Result<OpenVerifyEnvelope, String> {
    let kind = KaigiRelation::Usage;
    envelope(kind, kind.prover()?.prove_usage(context, witness)?)
}
/// Decode the one exact public column for authenticated ledger-context comparison.
/// This performs structural validation only; it does not establish proof validity.
///
/// # Errors
/// Foreign metadata, malformed canonical Norito, wrong shape or scalar encoding.
pub fn public_instances(
    backend: &str,
    envelope: &OpenVerifyEnvelope,
) -> Result<Vec<Vec<Scalar>>, String> {
    let kind = validate_metadata(backend, envelope)?;
    let native = decode_native(kind, &envelope.proof_bytes)?;
    let public = native
        .public_inputs
        .into_iter()
        .map(|bytes| {
            Option::<Scalar>::from(Scalar::from_repr(bytes))
                .ok_or_else(|| "noncanonical native public scalar".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vec![public])
}
fn decode_native(kind: NativeRelationV1, bytes: &[u8]) -> Result<NativePipaRProofV1, String> {
    // All current fixed circuits are much smaller; this cap bounds a malicious
    // Norito container before allocation. Exact transcript/arity checks follow.
    if bytes.len() > 128 * 1024 {
        return Err("native proof container exceeds fixed bound".into());
    }
    let native: NativePipaRProofV1 =
        norito::decode_canonical(bytes).map_err(|error| error.to_string())?;
    if native.public_inputs.len() != kind.instance_rows()
        || native.proof.len() != kind.proof_length()?
    {
        return Err("wrong native proof shape".into());
    }
    Ok(native)
}
pub(super) fn verify(backend: &str, proof: &ProofBox, key: Option<&VerifyingKeyBox>) -> bool {
    let verified = || -> Result<(), String> {
        if proof.backend != backend || proof.bytes.len() > super::MAX_PROOF_LEN {
            return Err("invalid native proof container".into());
        }
        let key = key.ok_or_else(|| "native proof requires a trusted key".to_owned())?;
        let outer: OpenVerifyEnvelope =
            norito::decode_canonical(&proof.bytes).map_err(|error| error.to_string())?;
        outer
            .validate_for_admission()
            .map_err(|error| error.to_string())?;
        let kind = validate_metadata(backend, &outer)?;
        if outer.vk_hash != super::hash_vk(key) {
            return Err("native verifier key hash mismatch".into());
        }
        validate_key(backend, &outer.circuit_id, key)?;
        let native = decode_native(kind, &outer.proof_bytes)?;
        kind.verify(&native.public_inputs, &native.proof)
    };
    verified().is_ok()
}

#[cfg(test)]
#[path = "native_pipa_r_tests.rs"]
mod tests;
