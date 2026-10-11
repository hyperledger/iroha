//! Exact first-release authenticated-owner PRF transcripts, without encryption claims.

use crate::{NetworkId, ram_lfe::RamLfeProgramId};
use iroha_crypto::{Hash, PolicyCommitment, RamLfeBackend, RamLfeError};
use zeroize::{Zeroize, Zeroizing};

/// Stable canonical PRF input scoped to the exact network and program.
/// A transport nonce never changes the canonical identifier nullifier.
///
/// # Errors
/// Rejects empty or overlong input and returns native canonical encoding failures.
pub fn hkdf_identifier_request_payload_v1(
    network: &NetworkId,
    program: &RamLfeProgramId,
    normalized_input: &str,
) -> Result<Vec<u8>, norito::Error> {
    if normalized_input.is_empty() || normalized_input.len() > 512 {
        return Err(norito::Error::Message(
            "identifier normalized input must contain 1..=512 bytes".to_owned(),
        ));
    }
    let mut input = (
        "iroha:identifier:v1:authenticated-owner-prf",
        *network,
        program.clone(),
        normalized_input.to_owned(),
    );
    let encoded = norito::encode_canonical(&input);
    input.3.zeroize();
    encoded
}

/// Bind exact native normalized input without publishing its low-entropy raw hash.
/// The caller retains the random nonce privately across the prepare/claim exchange.
///
/// # Errors
/// Rejects a zero nonce, invalid input, or native canonical encoding failure.
pub fn hkdf_identifier_input_commitment_v1(
    network: &NetworkId,
    program: &RamLfeProgramId,
    normalized_input: &str,
    nonce: &[u8; 32],
) -> Result<Hash, norito::Error> {
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(norito::Error::Message(
            "identifier private input nonce must not be zero".to_owned(),
        ));
    }
    let input = Zeroizing::new(hkdf_identifier_request_payload_v1(
        network,
        program,
        normalized_input,
    )?);
    Ok(Hash::new_from_chunks(&[
        b"iroha:identifier:v1:private-input-commitment\0",
        nonce,
        input.as_slice(),
    ]))
}

/// Exact receipt metadata authenticated by a production-supported HKDF policy.
/// There is no BFV evaluation key in this PRF corridor.
///
/// # Errors
/// Rejects diagnostic or unsupported backends before processing private material.
pub fn hkdf_identifier_execution_metadata_v1(
    commitment: &PolicyCommitment,
) -> Result<(Hash, Hash, Hash), RamLfeError> {
    commitment.backend.require_production_support()?;
    if commitment.backend != RamLfeBackend::HkdfSha3_512PrfV1 {
        return Err(RamLfeError::UnsupportedBackend(
            "identifier owner PRF requires HKDF".to_owned(),
        ));
    }
    let parameters = Hash::new(&commitment.public_parameters);
    let evaluation = Hash::new_from_chunks(&[
        b"iroha:identifier:v1:hkdf-no-evaluation-key\0",
        commitment.policy_hash.as_ref(),
        parameters.as_ref(),
    ]);
    Ok((commitment.policy_hash, parameters, evaluation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_commitment_changes_with_nonce_while_prf_input_is_stable() {
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"network"),
        ));
        let program = "phone_retail".parse().unwrap();
        let input = hkdf_identifier_request_payload_v1(&network, &program, "+6771234567").unwrap();
        assert_eq!(
            input,
            hkdf_identifier_request_payload_v1(&network, &program, "+6771234567").unwrap()
        );
        let first =
            hkdf_identifier_input_commitment_v1(&network, &program, "+6771234567", &[1; 32])
                .unwrap();
        assert_ne!(
            first,
            hkdf_identifier_input_commitment_v1(&network, &program, "+6771234567", &[2; 32])
                .unwrap()
        );
        assert_ne!(
            first,
            hkdf_identifier_input_commitment_v1(&network, &program, "+6777654321", &[1; 32])
                .unwrap()
        );
        assert_ne!(
            first,
            hkdf_identifier_input_commitment_v1(
                &NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                    Hash::new(b"other")
                )),
                &program,
                "+6771234567",
                &[1; 32]
            )
            .unwrap()
        );
    }

    #[test]
    fn receipt_metadata_pins_policy_and_public_parameters_and_rejects_bfv() {
        let mut commitment = PolicyCommitment {
            backend: RamLfeBackend::HkdfSha3_512PrfV1,
            policy_hash: Hash::new(b"policy"),
            public_parameters: vec![1],
        };
        let original = hkdf_identifier_execution_metadata_v1(&commitment).unwrap();
        commitment.public_parameters.push(2);
        assert_ne!(
            original,
            hkdf_identifier_execution_metadata_v1(&commitment).unwrap()
        );
        commitment.backend = RamLfeBackend::BfvProgrammedV1;
        assert!(hkdf_identifier_execution_metadata_v1(&commitment).is_err());
    }
    #[test]
    fn exact_input_bounds_and_nonce_are_mandatory() {
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"network"),
        ));
        let program = "phone_retail".parse().unwrap();
        assert!(hkdf_identifier_request_payload_v1(&network, &program, "").is_err());
        assert!(hkdf_identifier_request_payload_v1(&network, &program, &"x".repeat(513)).is_err());
        assert!(hkdf_identifier_request_payload_v1(&network, &program, &"x".repeat(512)).is_ok());
        assert!(hkdf_identifier_input_commitment_v1(&network, &program, "a", &[0; 32]).is_err());
        let owned = norito::encode_canonical(&(
            "iroha:identifier:v1:authenticated-owner-prf",
            network,
            program.clone(),
            "a".to_owned(),
        ))
        .unwrap();
        assert_eq!(
            owned,
            hkdf_identifier_request_payload_v1(&network, &program, "a").unwrap()
        );
    }
}
