//! Restored phone claims enforce the same signed native policy as registration.

use super::*;
use iroha_crypto::{Algorithm, KeyPair, PolicyCommitment, RamLfeBackend, RamLfeVerificationMode};
use iroha_data_model::identifier::{IdentifierNormalization, IdentifierPolicyId};
use iroha_test_samples::{ALICE_ID, BOB_ID};

fn program_id() -> RamLfeProgramId {
    "phone_retail".parse().unwrap()
}

fn policy_id() -> IdentifierPolicyId {
    "phone#retail".parse().unwrap()
}

fn public_key(seed: u8) -> iroha_crypto::PublicKey {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone()
}

fn world() -> World {
    world_with_program(program_id())
}

fn world_with_program(program_id: RamLfeProgramId) -> World {
    let account_id = ALICE_ID.clone();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"restored-phone-account"));
    let nullifier = Hash::new(b"restored-phone-secret-keyed-nullifier");
    let (opaque_hash, receipt_hash) = iroha_crypto::identifier_hashes_from_output_hash(
        &norito::encode_canonical(&program_id).unwrap(),
        &nullifier,
    );
    let opaque_id = OpaqueAccountId::from(opaque_hash);
    let account = Account::new(account_id.clone())
        .with_uaid(Some(uaid))
        .with_opaque_ids(vec![opaque_id])
        .build(&account_id);
    let mut world = World::with([], [account], []);
    let policy = IdentifierPolicy::new(
        policy_id(),
        account_id.clone(),
        IdentifierNormalization::PhoneE164,
        program_id.clone(),
    )
    .with_phone_retail_attestor_public_key(public_key(41));
    let program = RamLfeProgramPolicy::new(
        program_id.clone(),
        account_id.clone(),
        RamLfeBackend::HkdfSha3_512PrfV1,
        RamLfeVerificationMode::Signed,
        PolicyCommitment {
            backend: RamLfeBackend::HkdfSha3_512PrfV1,
            policy_hash: Hash::new(b"restored-phone-policy"),
            public_parameters: Vec::new(),
        },
        public_key(42),
    )
    .with_output_opening_public_key(public_key(43));
    world.identifier_policies = [(policy_id(), policy)].into_iter().collect();
    world.ram_lfe_program_policies = [(program_id, program)].into_iter().collect();
    world.identifier_claims = [(
        opaque_id,
        IdentifierClaimRecord {
            policy_id: policy_id(),
            opaque_id,
            receipt_hash,
            phone_retail_nullifier: Some(nullifier),
            uaid,
            account_id,
            verified_at_ms: 100,
            expires_at_ms: Some(200),
        },
    )]
    .into_iter()
    .collect();
    world
}

fn change_program(world: &mut World, mutate: impl FnOnce(&mut RamLfeProgramPolicy)) {
    let mut policies = world.ram_lfe_program_policies.block();
    mutate(policies.get_mut(&program_id()).unwrap());
    policies.commit();
}

fn change_policy(world: &mut World, mutate: impl FnOnce(&mut IdentifierPolicy)) {
    let mut policies = world.identifier_policies.block();
    mutate(policies.get_mut(&policy_id()).unwrap());
    policies.commit();
}

#[test]
fn restored_signed_hkdf_phone_claim_accepts_inactive_policies() {
    // Deactivation prevents new claims; it does not invalidate retained bindings.
    world().validate_identifier_claims().unwrap();
}

#[test]
fn snapshot_parser_preserves_signed_hkdf_phone_binding_and_rejects_shared_attestor() {
    let original = world();
    let restored = deserialize::decode_world_component_for_testing(&original).unwrap();
    assert_eq!(
        restored.identifier_claims.view().iter().collect::<Vec<_>>(),
        original.identifier_claims.view().iter().collect::<Vec<_>>()
    );
    assert_eq!(
        restored.opaque_uaids.view().iter().collect::<Vec<_>>(),
        original.opaque_uaids.view().iter().collect::<Vec<_>>()
    );
    restored.validate_identifier_claims().unwrap();

    let mut tampered = world();
    change_policy(&mut tampered, |policy| {
        policy.phone_retail_attestor_public_key = Some(public_key(42));
    });
    let error = deserialize::decode_world_component_for_testing(&tampered)
        .err()
        .expect("a resolver cannot certify its own phone canonicality");
    assert!(error.to_string().contains("attestor must be independent"));
}

#[test]
fn snapshot_parser_rejects_phone_registry_key_with_non_phone_policy_identity() {
    // Every account/index/nullifier binding is consistent with the other program.
    // The contradictory registry identity must still reject before classifying
    // the embedded policy as an ordinary non-phone policy without an attestor.
    let mut tampered = world_with_program("other_program".parse().unwrap());
    change_policy(&mut tampered, |policy| {
        policy.id = "email#retail".parse().unwrap();
        policy.normalization = IdentifierNormalization::Exact;
        policy.phone_retail_attestor_public_key = None;
    });
    let error = deserialize::decode_world_component_for_testing(&tampered)
        .err()
        .expect("registry identity cannot downgrade a phone claim");
    assert!(
        error
            .to_string()
            .contains("Identifier policy key phone#retail")
    );
    assert!(
        error
            .to_string()
            .contains("embedded policy id email#retail")
    );
}

#[test]
fn snapshot_parser_rejects_unclaimed_identifier_policy_key_mismatch() {
    let tampered = world();
    let mut policy = tampered
        .identifier_policies
        .view()
        .get(&policy_id())
        .unwrap()
        .clone();
    policy.id = "email#retail".parse().unwrap();
    let mut policies = tampered.identifier_policies.block();
    policies.insert("email#other".parse().unwrap(), policy);
    policies.commit();
    let error = deserialize::decode_world_component_for_testing(&tampered)
        .err()
        .expect("unclaimed registry entries must retain their exact identity");
    assert!(
        error
            .to_string()
            .contains("Identifier policy key email#other")
    );
}

#[test]
fn snapshot_parser_rejects_unreferenced_program_policy_key_mismatch() {
    let tampered = world();
    let program = tampered
        .ram_lfe_program_policies
        .view()
        .get(&program_id())
        .unwrap()
        .clone();
    let mut programs = tampered.ram_lfe_program_policies.block();
    programs.insert("unreferenced_program".parse().unwrap(), program);
    programs.commit();
    let error = deserialize::decode_world_component_for_testing(&tampered)
        .err()
        .expect("unreferenced program entries must retain their exact identity");
    assert!(
        error
            .to_string()
            .contains("RAM-LFE program policy key unreferenced_program")
    );
    assert!(
        error
            .to_string()
            .contains("embedded program id phone_retail")
    );
}

#[test]
fn restored_phone_claim_rejects_both_diagnostic_backend_fields() {
    for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
        for commitment_only in [false, true] {
            let mut world = world();
            change_program(&mut world, |program| {
                program.commitment.backend = backend;
                if !commitment_only {
                    program.backend = backend;
                }
            });
            let error = world.validate_identifier_claims().unwrap_err();
            assert!(error.contains("noiseless public-key equation"), "{error}");
        }
    }
}

#[test]
fn restored_phone_claim_rejects_changed_owner_program_and_proof_mode() {
    let mutations: [fn(&mut RamLfeProgramPolicy); 3] = [
        |program| program.owner = BOB_ID.clone(),
        |program| program.program_id = "other_program".parse().unwrap(),
        |program| program.verification_mode = RamLfeVerificationMode::Proof,
    ];
    for mutate in mutations {
        let mut world = world();
        change_program(&mut world, mutate);
        let error = world.validate_identifier_claims().unwrap_err();
        assert!(
            error.contains("owner-pinned signed native HKDF policy"),
            "{error}"
        );
    }
}

#[test]
fn restored_phone_claim_requires_independent_attestor() {
    for seed in [42, 43] {
        let mut world = world();
        change_policy(&mut world, |policy| {
            policy.phone_retail_attestor_public_key = Some(public_key(seed));
        });
        let error = world.validate_identifier_claims().unwrap_err();
        assert!(error.contains("attestor must be independent"), "{error}");
    }
    let mut world = world();
    change_policy(&mut world, |policy| {
        policy.phone_retail_attestor_public_key = None
    });
    assert!(
        world
            .validate_identifier_claims()
            .unwrap_err()
            .contains("pinned canonicality attestor")
    );
}

#[test]
fn restored_phone_claim_rejects_changed_normalization_and_nullifier() {
    let mut wrong_policy = world();
    change_policy(&mut wrong_policy, |policy| {
        policy.normalization = IdentifierNormalization::Exact;
    });
    assert!(
        wrong_policy
            .validate_identifier_claims()
            .unwrap_err()
            .contains("PhoneE164")
    );
    let wrong_nullifier = world();
    let mut claims = wrong_nullifier.identifier_claims.block();
    let opaque_id = *claims.iter().next().unwrap().0;
    claims.get_mut(&opaque_id).unwrap().phone_retail_nullifier =
        Some(Hash::new(b"different-nullifier"));
    claims.commit();
    assert!(
        wrong_nullifier
            .validate_identifier_claims()
            .unwrap_err()
            .contains("canonical nullifier index")
    );
}
