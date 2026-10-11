//! Purpose-bound verification of the actual compiled OpenVerify relations.
//!
//! Backend names identify arithmetic engines, not application guarantees. The
//! caller supplies the required relation; it is checked before cryptographic
//! work and cannot be selected by the submitted proof. Ledger consumers still
//! authenticate the active key, public statement, authority and replay state.

use std::time::Duration;

use iroha_data_model::{
    proof::{ProofBox, VerifyingKeyBox},
    zk::{BackendTag, OpenVerifyEnvelope},
};

use super::ZkVerifyGuardrails;

/// Exact statement established by one compiled generic verifier.
///
/// This describes the relation, not production qualification or authorization.
/// The complete IVM execution relation is not yet admitted; no binding-only
/// substitute can select an IVM relation through this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofRelation {
    /// Native STARK binding of public bytes to a deterministic public trace.
    /// This supplies no application-specific private-witness relation.
    PublicInputBinding,
    /// Ownership, membership, range and conservation for a confidential transfer.
    /// Consumed and created note commitments remain public and linkable.
    ConfidentialTransfer,
    /// Ownership, membership, range and conservation for complete redemption.
    ConfidentialFullUnshield,
    /// Ownership, membership, range and conservation for redemption with private change.
    ConfidentialChangeUnshield,
    /// Kaigi authorization bound to the public call, subject, role and sequence.
    KaigiAuthorization,
    /// Kaigi usage bound to the public call, host, segment and billed tuple.
    KaigiUsage,
}

/// Successful cryptographic verification for the caller's required relation.
///
/// Only the verifier can construct this value. It is not a ledger authorization:
/// active-key lookup, exact application public inputs, permissions and replay
/// checks belong to the consuming state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedProof {
    relation: ProofRelation,
    elapsed: Duration,
}

impl VerifiedProof {
    /// Return the exact caller-required relation that was verified.
    #[must_use]
    pub const fn relation(self) -> ProofRelation {
        self.relation
    }

    /// Return backend verification time for diagnostics, never consensus validity.
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }
}

/// Actionable rejection before or during purpose-bound verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofVerificationError {
    /// The backend label has no admitted native verifier.
    #[error("unsupported proof backend")]
    UnsupportedBackend,
    /// Node policy has disabled this arithmetic backend.
    #[error("proof backend is disabled by verification policy")]
    BackendDisabled,
    /// The outer bytes exceed the configured bound before decoding.
    #[error("proof envelope is {actual} bytes; configured maximum is {maximum}")]
    EnvelopeTooLarge {
        /// Supplied envelope byte count.
        actual: usize,
        /// Maximum allowed envelope byte count.
        maximum: usize,
    },
    /// The canonical envelope or its backend identity is invalid.
    #[error("malformed or noncanonical proof envelope")]
    MalformedEnvelope,
    /// No compiled generic relation exists for this circuit/backend pair.
    #[error("circuit has no supported generic proof relation; use its dedicated protocol verifier")]
    UnsupportedRelation,
    /// A proof of another statement cannot satisfy the caller's requirement.
    #[error("expected proof relation {expected:?}, but the circuit establishes {actual:?}")]
    RelationMismatch {
        /// Relation explicitly required by the caller.
        expected: ProofRelation,
        /// Relation selected by the submitted circuit.
        actual: ProofRelation,
    },
    /// The trusted key's backend or digest differs from the proof's binding.
    #[error("proof does not bind the supplied verifying key")]
    VerifyingKeyMismatch,
    /// The inner native proof exceeds the configured byte limit.
    #[error("native proof is {actual} bytes; configured maximum is {maximum}")]
    ProofTooLarge {
        /// Supplied inner native proof byte count.
        actual: usize,
        /// Maximum native proof byte count allowed by policy.
        maximum: usize,
    },
    /// Key format, proof shape, public instance or cryptographic verification failed.
    #[error("proof or verifying key failed cryptographic verification")]
    InvalidProof,
}

/// Verify a proof only for the explicitly required compiled relation.
///
/// No entropy or prover work is needed. Byte caps, backend policy and relation
/// mismatch are checked before native verification. The key must come from the
/// caller's trusted source; this function does not query chain state.
///
/// # Errors
///
/// Returns a typed [`ProofVerificationError`] for unavailable policy, malformed
/// input, the wrong relation, or a rejected cryptographic proof. In particular,
/// a valid public binding proof cannot stand in for a confidential transfer.
///
/// ```no_run
/// use iroha_core_zk::{ProofRelation, ZkVerifyGuardrails, verify_for_relation};
/// # fn example(proof: &iroha_data_model::proof::ProofBox,
/// # key: &iroha_data_model::proof::VerifyingKeyBox,
/// # guardrails: ZkVerifyGuardrails)
/// # -> Result<(), iroha_core_zk::ProofVerificationError> {
/// // Resolve the active key and authenticate the application's public inputs first.
/// let verified = verify_for_relation(ProofRelation::KaigiAuthorization, proof, key, guardrails)?;
/// assert_eq!(verified.relation(), ProofRelation::KaigiAuthorization);
/// # Ok(())
/// # }
/// ```
pub fn verify_for_relation(
    required: ProofRelation,
    proof: &ProofBox,
    key: &VerifyingKeyBox,
    policy: ZkVerifyGuardrails,
) -> Result<VerifiedProof, ProofVerificationError> {
    let backend = proof.backend.as_str();
    let tag = super::production_verify_backend_tag(backend)
        .ok_or(ProofVerificationError::UnsupportedBackend)?;
    let (enabled, maximum, proof_maximum) = match tag {
        BackendTag::NativePipaRPasta => (
            policy.pipa_r_enabled,
            policy.pipa_r_max_envelope_bytes,
            policy.pipa_r_max_proof_bytes,
        ),
        BackendTag::Stark => (
            policy.stark_enabled,
            policy.stark_max_envelope_bytes,
            policy.stark_max_proof_bytes,
        ),
    };
    if !enabled {
        return Err(ProofVerificationError::BackendDisabled);
    }
    if proof.bytes.len() > maximum {
        return Err(ProofVerificationError::EnvelopeTooLarge {
            actual: proof.bytes.len(),
            maximum,
        });
    }
    let envelope: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes)
        .map_err(|_| ProofVerificationError::MalformedEnvelope)?;
    if envelope.backend != tag {
        return Err(ProofVerificationError::MalformedEnvelope);
    }
    if envelope.proof_bytes.len() > proof_maximum {
        return Err(ProofVerificationError::ProofTooLarge {
            actual: envelope.proof_bytes.len(),
            maximum: proof_maximum,
        });
    }
    let actual = compiled_relation(backend, &envelope.circuit_id)
        .ok_or(ProofVerificationError::UnsupportedRelation)?;
    if actual != required {
        return Err(ProofVerificationError::RelationMismatch {
            expected: required,
            actual,
        });
    }
    if key.backend != proof.backend || envelope.vk_hash != super::hash_vk(key) {
        return Err(ProofVerificationError::VerifyingKeyMismatch);
    }
    let report = super::verify_backend_with_timing_guardrails(backend, proof, Some(key), policy);
    if !report.ok {
        return Err(ProofVerificationError::InvalidProof);
    }
    Ok(VerifiedProof {
        relation: actual,
        elapsed: report.elapsed,
    })
}

fn compiled_relation(backend: &str, circuit: &str) -> Option<ProofRelation> {
    if let Some(kind) = super::native_pipa_r::relation(backend, circuit) {
        return Some(match kind {
            super::native_pipa_r::NativeRelationV1::KaigiAuthorization => {
                ProofRelation::KaigiAuthorization
            }
            super::native_pipa_r::NativeRelationV1::KaigiUsage => ProofRelation::KaigiUsage,
            super::native_pipa_r::NativeRelationV1::ConfidentialTransfer => {
                ProofRelation::ConfidentialTransfer
            }
            super::native_pipa_r::NativeRelationV1::ConfidentialFullUnshield => {
                ProofRelation::ConfidentialFullUnshield
            }
            super::native_pipa_r::NativeRelationV1::ConfidentialChangeUnshield => {
                ProofRelation::ConfidentialChangeUnshield
            }
        });
    }
    if !super::stark_open_verify_circuit_id_matches_backend(backend, circuit)
        || super::canonical_circuit_is_zk_ace_relation_for_backend(backend, circuit)
        || super::canonical_circuit_is_governance_vote_relation_for_backend(backend, circuit)
        || super::canonical_circuit_is_soracloud_fhe_relation_for_backend(backend, circuit)
        || super::canonical_bfv_full_bootstrap_stark_circuit_id_for_backend(backend).as_deref()
            == Some(circuit)
    {
        return None;
    }
    Some(ProofRelation::PublicInputBinding)
}

#[cfg(test)]
mod tests;
