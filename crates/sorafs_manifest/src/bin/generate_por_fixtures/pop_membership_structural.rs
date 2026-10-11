// Shared wire-shape fixtures only: no cryptographic proof or recipient authorization is asserted.

fn pop_structural_membership_proof() -> sorafs_manifest::PopMembershipProofV1 {
    use sorafs_manifest::pop_credentials::{
        POP_CREDENTIAL_TREE_DEPTH_V1, POP_MEMBERSHIP_PROOF_VERSION_V1,
        POP_REVOCATION_TREE_DEPTH_V1, PopEligibilityClassV1, PopMembershipProofSystemV1,
        PopMembershipVerifierMaterialV1,
    };
    let mut scalar = [0; 32];
    scalar[0] = 1;
    sorafs_manifest::PopMembershipProofV1 {
        version: POP_MEMBERSHIP_PROOF_VERSION_V1,
        eligibility_class: PopEligibilityClassV1::General,
        commitment_root: scalar,
        commitment_tree_version: 7,
        revocation_root: scalar,
        revocation_list_version: 3,
        nullifier: scalar,
        challenge_digest: [0x43; 32],
        verifier_context: "structural-sdk-fixture".to_owned(),
        presentation_binding_digest: [0x46; 32],
        proof_system: PopMembershipProofSystemV1::NativePipaRV1,
        verifier_material: PopMembershipVerifierMaterialV1 {
            circuit_id: "sorafs-pop-membership-pipa-r-v1".to_owned(),
            circuit_k: 14,
            credential_tree_depth: POP_CREDENTIAL_TREE_DEPTH_V1,
            revocation_tree_depth: POP_REVOCATION_TREE_DEPTH_V1,
            parameter_digest: [0x44; 32],
            verifying_key_digest: [0x45; 32],
        },
        // Deliberately not a cryptographic proof: the public API exercised by
        // these fixtures validates the wire shape and nonzero metadata only.
        proof_bytes: vec![0xAA; 64],
        expires_at_epoch: 2_000,
    }
}

type PopStructuralFixture = (String, Vec<u8>);

fn pop_membership_structural_fixtures() -> Result<Vec<PopStructuralFixture>, Box<dyn Error>> {
    use sorafs_manifest::{PopMembershipProofV1, PopValidationPayloadKindV1};
    // This intentionally incomplete field order is confined to fixture generation.
    // Its frame advertises the actual current schema, so the decoder must detect
    // the missing binding itself, not merely a different test-type schema hash.
    #[derive(NoritoSerialize)]
    struct MissingPresentationBinding {
        version: u8,
        eligibility_class: sorafs_manifest::PopEligibilityClassV1,
        commitment_root: [u8; 32],
        commitment_tree_version: u64,
        revocation_root: [u8; 32],
        revocation_list_version: u64,
        nullifier: [u8; 32],
        challenge_digest: [u8; 32],
        verifier_context: String,
        proof_system: sorafs_manifest::PopMembershipProofSystemV1,
        verifier_material: sorafs_manifest::pop_credentials::PopMembershipVerifierMaterialV1,
        proof_bytes: Vec<u8>,
        expires_at_epoch: u64,
    }
    let current = pop_structural_membership_proof();
    current.validate()?;
    let current_bytes = norito::encode_canonical(&current)?;
    if norito::decode_canonical::<PopMembershipProofV1>(&current_bytes)? != current {
        return Err("PoP structural fixture changed during canonical roundtrip".into());
    }
    let missing = MissingPresentationBinding {
        version: current.version,
        eligibility_class: current.eligibility_class,
        commitment_root: current.commitment_root,
        commitment_tree_version: current.commitment_tree_version,
        revocation_root: current.revocation_root,
        revocation_list_version: current.revocation_list_version,
        nullifier: current.nullifier,
        challenge_digest: current.challenge_digest,
        verifier_context: current.verifier_context.clone(),
        proof_system: current.proof_system,
        verifier_material: current.verifier_material.clone(),
        proof_bytes: current.proof_bytes.clone(),
        expires_at_epoch: current.expires_at_epoch,
    };
    let missing_bytes = {
        let _canonical =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let (payload, flags) = norito::codec::encode_with_header_flags(&missing);
        norito::core::frame_bare_with_header_flags::<PopMembershipProofV1>(&payload, flags)?
    };
    match norito::decode_from_bytes::<PopMembershipProofV1>(&missing_bytes) {
        Err(norito::Error::SchemaMismatch) | Ok(_) => {
            return Err(
                "missing-binding fixture must fail inside the actual current schema".into(),
            );
        }
        Err(_) => {}
    }
    let mut zero = current;
    zero.presentation_binding_digest = [0; 32];
    if zero.validate()
        != Err(
            sorafs_manifest::PopCredentialValidationError::InvalidDigest {
                field: "presentation binding digest",
            },
        )
    {
        return Err("zero-binding fixture must fail its exact structural invariant".into());
    }
    let zero_bytes = norito::encode_canonical(&zero)?;
    let profiles = [
        (
            "pop_membership_current_v1",
            current_bytes,
            true,
            "SFS-OK-000",
        ),
        (
            "pop_membership_missing_binding_v1",
            missing_bytes,
            false,
            "SFS-NORITO-001",
        ),
        (
            "pop_membership_zero_binding_v1",
            zero_bytes,
            false,
            "SFS-VAL-001",
        ),
    ];
    let mut fixtures = Vec::with_capacity(profiles.len() * 2);
    for (name, bytes, expected_ok, expected_code) in profiles {
        let label = format!("{name}.to");
        let outcome = sorafs_manifest::validate_pop_payload_bytes(
            PopValidationPayloadKindV1::MembershipProof,
            &bytes,
            &label,
            123,
        );
        if outcome.is_ok() != expected_ok || outcome.code != expected_code {
            return Err(format!(
                "PoP structural fixture {name} returned {}, expected {expected_code}",
                outcome.code
            )
            .into());
        }
        fixtures.push((label, bytes));
        fixtures.push((
            format!("{name}_validation_outcome.json"),
            format!("{}\n", to_string_pretty(&outcome)?).into_bytes(),
        ));
    }
    Ok(fixtures)
}

fn write_pop_membership_structural_fixtures(directory: &Path) -> Result<(), Box<dyn Error>> {
    for (name, bytes) in pop_membership_structural_fixtures()? {
        write_new_regular_file(&directory.join(name), &bytes)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod pop_structural_tests {
    use super::*;

    #[test]
    fn membership_structural_fixtures_are_deterministic_and_reject_missing_or_zero_binding() {
        let fixtures = pop_membership_structural_fixtures().expect("generate structural fixtures");
        assert_eq!(fixtures.len(), 6);
        assert_eq!(fixtures, pop_membership_structural_fixtures().unwrap());
        assert!(fixtures.iter().all(|(_, bytes)| !bytes.is_empty()));
        let directory = tempfile::tempdir().unwrap();
        let physical_directory = fs::canonicalize(directory.path()).unwrap();
        write_pop_membership_structural_fixtures(&physical_directory).unwrap();
        for (name, bytes) in fixtures {
            assert_eq!(fs::read(directory.path().join(name)).unwrap(), bytes);
        }
    }
}
