//! Adapters from the State-owned ZK settings to zk verification guardrails.
//!
//! The verifier in [`crate::zk`] only consumes scalar [`ZkVerifyGuardrails`];
//! this module maps the ZK settings a block or view froze onto those caps.
//! Their validity values are the committed `zk_validity_policy_v1` parameter
//! or the protocol default ([`crate::zk_validity_policy`]), never a node's own
//! configuration.

use iroha_config::parameters::actual::Zk;
use iroha_data_model::proof::{ProofBox, VerifyingKeyBox};

use crate::zk::{VerifyReport, ZkVerifyGuardrails, verify_backend_with_timing_guardrails};

/// Build verification guardrails from the ZK settings a block or view froze.
#[inline]
#[must_use]
pub fn guardrails_from_config(cfg: &Zk) -> ZkVerifyGuardrails {
    ZkVerifyGuardrails {
        halo2_enabled: cfg.halo2.enabled,
        halo2_max_envelope_bytes: cfg.halo2.max_envelope_bytes,
        halo2_max_proof_bytes: cfg.halo2.max_proof_bytes,
        stark_enabled: cfg.stark.enabled,
        stark_max_envelope_bytes: cfg.stark.max_envelope_bytes,
        stark_max_proof_bytes: cfg.stark.max_proof_bytes,
    }
}

/// Verify a backend under the frozen policy guardrails (enabled flags + payload size caps).
///
/// This helper exists to prevent accidentally accepting proofs for a backend that is
/// compiled in but disabled at runtime.
#[inline]
#[must_use]
pub fn verify_backend_with_timing_checked(
    backend: &str,
    proof: &ProofBox,
    vk: Option<&VerifyingKeyBox>,
    cfg: &Zk,
) -> VerifyReport {
    verify_backend_with_timing_guardrails(backend, proof, vk, guardrails_from_config(cfg))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::state::default_zk_config;

    #[test]
    fn guardrails_from_config_copies_every_cap() {
        let mut cfg = default_zk_config();
        cfg.halo2.enabled = true;
        cfg.halo2.max_envelope_bytes = 11;
        cfg.halo2.max_proof_bytes = 12;
        cfg.stark.enabled = false;
        cfg.stark.max_envelope_bytes = 13;
        cfg.stark.max_proof_bytes = 14;
        assert_eq!(
            guardrails_from_config(&cfg),
            ZkVerifyGuardrails {
                halo2_enabled: true,
                halo2_max_envelope_bytes: 11,
                halo2_max_proof_bytes: 12,
                stark_enabled: false,
                stark_max_envelope_bytes: 13,
                stark_max_proof_bytes: 14,
            }
        );
    }

    #[test]
    fn checked_verification_rejects_disabled_backend() {
        let mut cfg = default_zk_config();
        cfg.halo2.enabled = false;
        let proof = ProofBox::new("halo2/ipa".into(), vec![0xAA; 8]);
        let report = verify_backend_with_timing_checked("halo2/ipa", &proof, None, &cfg);
        assert!(!report.ok);
        assert_eq!(report.elapsed, Duration::ZERO);
    }
}
