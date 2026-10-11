// Component and refusal tests; synthetic metadata never admits encrypted execution.
use super::*;
use crate::{kura::Kura, prelude::World, query::store::LiveQueryStore, state::State};
use iroha_crypto::{
    Algorithm, KeyPair, PolicyCommitment, PrivateKey, Signature, SignatureOf,
    derive_phone_retail_nullifier_v1, ram_lfe_output_hash,
};
use iroha_data_model::{
    IntoKeyValue, NetworkId,
    account::{Account, OpaqueAccountId},
    block::BlockHeader,
    identifier::{
        IdentifierPolicyId, IdentifierResolutionReceiptPayload,
        PhoneRetailCanonicalityAttestationV1, PhoneRetailCanonicalityPayloadV1,
    },
    isi::identifier::{
        ActivateIdentifierPolicy, ClaimIdentifier, RegisterIdentifierPolicy, RevokeIdentifier,
    },
    isi::ram_lfe::{ActivateRamLfeProgramPolicy, RegisterRamLfeProgramPolicy},
    nexus::UniversalAccountId,
    prelude::Domain,
    ram_lfe::{RamLfeOutputOpeningPayload, RamLfeProgramId},
};
use iroha_model_base::{domain::DomainId, metadata::Metadata};
use nonzero_ext::nonzero;

fn test_state() -> State {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    State::new_for_testing(World::default(), kura, query)
}
fn checked_keypair() -> KeyPair {
    KeyPair::try_random().expect("identifier fixture key generation should succeed")
}
fn checked_account_id() -> AccountId {
    AccountId::new(checked_keypair().public_key().clone())
}
#[test]
fn checked_keypair_helper_preserves_default_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
}
fn checked_signature_of<T: norito::codec::Encode>(
    private_key: &PrivateKey,
    payload: &T,
) -> SignatureOf<T> {
    SignatureOf::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn seed_domain(state: &mut State, domain_id: &DomainId, owner: &AccountId) {
    let domain = Domain {
        id: domain_id.clone(),
        logo: None,
        metadata: Metadata::default(),
        owned_by: owner.clone(),
    };
    state.world.domains.insert(domain_id.clone(), domain);
}
fn seed_account_with_uaid(state: &mut State, account_id: &AccountId, uaid: UniversalAccountId) {
    let account = Account::new(account_id.clone())
        .with_uaid(Some(uaid))
        .into_account();
    let (account_id, account_value) = account.into_key_value();
    state
        .world
        .accounts
        .insert(account_id.clone(), account_value);
    state.world.uaid_accounts.insert(uaid, account_id.clone());
}
fn claim_receipt(
    policy_id: &IdentifierPolicyId,
    program_policy: &RamLfeProgramPolicy,
    resolver: &KeyPair,
    uaid: UniversalAccountId,
    account_id: &AccountId,
    resolved_at_ms: u64,
    expires_at_ms: Option<u64>,
    output_seed: &[u8],
) -> IdentifierResolutionReceipt {
    let output_hash = Hash::new([b"ciphertext:".as_slice(), output_seed].concat());
    let opened_output_hash = ram_lfe_output_hash(output_seed);
    let program_id_bytes =
        norito::encode_canonical(&program_policy.program_id).expect("encode canonical program id");
    let (opaque_id, receipt_hash) =
        identifier_hashes_from_output_hash(&program_id_bytes, &opened_output_hash);
    let execution = RamLfeExecutionReceiptPayload {
        program_id: program_policy.program_id.clone(),
        program_digest: Hash::new(b"typed-program-digest"),
        backend: program_policy.backend,
        verification_mode: program_policy.verification_mode,
        input_ciphertext_hash: Hash::new(b"input-ciphertext"),
        output_ciphertext_hash: output_hash,
        parameter_digest: Hash::new(b"typed-parameter-digest"),
        evaluation_key_digest: Hash::new(b"typed-evaluation-key-digest"),
        output_hash,
        associated_data_hash: Hash::new([]),
        executed_at_ms: resolved_at_ms,
        expires_at_ms,
    };
    let opening_payload = RamLfeOutputOpeningPayload {
        program_id: program_policy.program_id.clone(),
        input_ciphertext_hash: execution.input_ciphertext_hash,
        output_ciphertext_hash: execution.output_ciphertext_hash,
        parameter_digest: execution.parameter_digest,
        evaluation_key_digest: execution.evaluation_key_digest,
        opened_output_hash,
        opened_at_ms: resolved_at_ms.saturating_add(1),
        expires_at_ms,
    };
    let opening = RamLfeOutputOpening {
        signature: checked_signature_of(resolver.private_key(), &opening_payload).into(),
        payload: opening_payload,
    };
    let payload = IdentifierResolutionReceiptPayload {
        network_id: *test_state().network_id_ref(),
        policy_id: policy_id.clone(),
        execution,
        opening,
        opaque_id: OpaqueAccountId::from(opaque_id),
        receipt_hash,
        uaid,
        account_id: account_id.clone(),
    };
    let signature: Signature = checked_signature_of(resolver.private_key(), &payload).into();
    IdentifierResolutionReceipt {
        payload,
        attestation: RamLfeReceiptAttestation::Signed(signature),
        phone_retail_canonicality: None,
    }
}
fn attach_phone_retail_canonicality(
    receipt: &mut IdentifierResolutionReceipt,
    attestor: &KeyPair,
    opener: &KeyPair,
    network_id: &NetworkId,
    canonical_phone: &str,
) -> Hash {
    let nullifier = derive_phone_retail_nullifier_v1(
        &[0x5a; Hash::LENGTH],
        network_id.as_bytes(),
        canonical_phone,
    )
    .expect("derive canonical phone nullifier");
    // This is a private binding/canonicality component fixture with diagnostic
    // execution metadata. It does not qualify owner evaluation or ClaimIdentifier.
    receipt.payload.execution.output_hash = nullifier;
    receipt.payload.execution.output_ciphertext_hash = nullifier;
    receipt.payload.opening.payload.output_ciphertext_hash = nullifier;
    receipt.payload.opening.payload.opened_output_hash = nullifier;
    receipt.payload.opening.signature =
        checked_signature_of(opener.private_key(), &receipt.payload.opening.payload).into();
    let opening = &receipt.payload.opening.payload;
    let payload = PhoneRetailCanonicalityPayloadV1 {
        network_id: *network_id,
        policy_id: receipt.payload.policy_id.clone(),
        program_id: receipt.payload.execution.program_id.clone(),
        input_ciphertext_hash: opening.input_ciphertext_hash,
        output_ciphertext_hash: opening.output_ciphertext_hash,
        opened_output_hash: opening.opened_output_hash,
        canonical_phone_nullifier: nullifier,
        uaid: receipt.payload.uaid,
        account_id: receipt.payload.account_id.clone(),
        issued_at_ms: opening.opened_at_ms,
        expires_at_ms: opening
            .expires_at_ms
            .expect("phone fixture needs an attestation expiry"),
    };
    receipt.phone_retail_canonicality = Some(PhoneRetailCanonicalityAttestationV1 {
        signature: checked_signature_of(attestor.private_key(), &payload).into(),
        payload,
    });
    nullifier
}
fn phone_retail_claim_receipt(
    policy_id: &IdentifierPolicyId,
    program_policy: &RamLfeProgramPolicy,
    resolver: &KeyPair,
    attestor: &KeyPair,
    network_id: &NetworkId,
    uaid: UniversalAccountId,
    account_id: &AccountId,
    resolved_at_ms: u64,
    expires_at_ms: u64,
    canonical_phone: &str,
) -> IdentifierResolutionReceipt {
    let mut receipt = claim_receipt(
        policy_id,
        program_policy,
        resolver,
        uaid,
        account_id,
        resolved_at_ms,
        Some(expires_at_ms),
        canonical_phone.as_bytes(),
    );
    let nullifier = attach_phone_retail_canonicality(
        &mut receipt,
        attestor,
        resolver,
        network_id,
        canonical_phone,
    );
    let program_id_bytes =
        norito::encode_canonical(&program_policy.program_id).expect("encode canonical program id");
    let (opaque_id, receipt_hash) =
        identifier_hashes_from_output_hash(&program_id_bytes, &nullifier);
    receipt.payload.opaque_id = OpaqueAccountId::from(opaque_id);
    receipt.payload.receipt_hash = receipt_hash;
    receipt.attestation = RamLfeReceiptAttestation::Signed(
        checked_signature_of(resolver.private_key(), &receipt.payload).into(),
    );
    receipt
}
fn phone_claim_receipt(
    policy_id: &IdentifierPolicyId,
    program_policy: &RamLfeProgramPolicy,
    resolver: &KeyPair,
    attestor: &KeyPair,
    network_id: NetworkId,
    uaid: UniversalAccountId,
    account_id: &AccountId,
    canonical_phone: &str,
    ciphertext_seed: &[u8],
    output_seed: &[u8],
    resolved_at_ms: u64,
) -> IdentifierResolutionReceipt {
    let mut receipt = claim_receipt(
        policy_id,
        program_policy,
        resolver,
        uaid,
        account_id,
        resolved_at_ms,
        Some(resolved_at_ms + 60_000),
        output_seed,
    );
    let input_hash = Hash::new(ciphertext_seed);
    receipt.payload.execution.input_ciphertext_hash = input_hash;
    receipt.payload.opening.payload.input_ciphertext_hash = input_hash;
    receipt.payload.opening.signature =
        checked_signature_of(resolver.private_key(), &receipt.payload.opening.payload).into();
    let nullifier = attach_phone_retail_canonicality(
        &mut receipt,
        attestor,
        resolver,
        &network_id,
        canonical_phone,
    );
    let program_bytes =
        norito::encode_canonical(&program_policy.program_id).expect("canonical program id");
    let (opaque, receipt_hash) = identifier_hashes_from_output_hash(&program_bytes, &nullifier);
    receipt.payload.opaque_id = OpaqueAccountId::from(opaque);
    receipt.payload.receipt_hash = receipt_hash;
    receipt.attestation = RamLfeReceiptAttestation::Signed(
        checked_signature_of(resolver.private_key(), &receipt.payload).into(),
    );
    receipt
}

fn sample_program_policy(
    owner: &AccountId,
    resolver: &KeyPair,
    program_id: &RamLfeProgramId,
) -> RamLfeProgramPolicy {
    RamLfeProgramPolicy::new(
        program_id.clone(),
        owner.clone(),
        RamLfeBackend::BfvProgrammedV1,
        RamLfeVerificationMode::Signed,
        PolicyCommitment {
            backend: RamLfeBackend::BfvProgrammedV1,
            policy_hash: Hash::new(b"typed-policy"),
            public_parameters: Vec::new(),
        },
        resolver.public_key().clone(),
    )
}

fn email_policy(owner: &AccountId) -> IdentifierPolicy {
    IdentifierPolicy::new(
        "email#retail".parse().unwrap(),
        owner.clone(),
        IdentifierNormalization::EmailAddress,
        "email_retail".parse().unwrap(),
    )
}

fn seeded_state(owner: &AccountId, uaid: UniversalAccountId) -> State {
    let mut state = test_state();
    let domain = DomainId::try_new("directory", "universal").unwrap();
    seed_account_with_uaid(&mut state, owner, uaid);
    seed_domain(&mut state, &domain, owner);
    state
}

#[test]
fn encrypted_registration_activation_and_claims_refuse_without_state_changes() {
    let owner = checked_account_id();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"refused-owner"));
    let state = seeded_state(&owner, uaid);
    let resolver = checked_keypair();
    let mut policy = email_policy(&owner);
    policy.active = true;
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1, 0));
    let mut tx = block.transaction();
    for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
        let mut candidate = program.clone();
        candidate.backend = backend;
        candidate.commitment.backend = backend;
        let error = RegisterRamLfeProgramPolicy {
            policy: candidate.clone(),
        }
        .execute(&owner, &mut tx)
        .expect_err("insecure registration must reject");
        assert!(
            error.to_string().contains("noiseless public-key equation"),
            "{error}"
        );
        assert!(
            tx.world
                .ram_lfe_program_policies
                .get(&program.program_id)
                .is_none()
        );
        // Seed invalid stored metadata only to prove activation/claim cannot bypass
        // the guard. No successful encrypted admission is used as a fixture.
        tx.world
            .ram_lfe_program_policies
            .insert(program.program_id.clone(), candidate.clone());
        let error = ActivateRamLfeProgramPolicy {
            program_id: program.program_id.clone(),
        }
        .execute(&owner, &mut tx)
        .expect_err("stored insecure policy cannot activate");
        assert!(
            error.to_string().contains("noiseless public-key equation"),
            "{error}"
        );
        assert!(
            !tx.world
                .ram_lfe_program_policies
                .get(&program.program_id)
                .unwrap()
                .active
        );
        candidate.active = true;
        tx.world
            .ram_lfe_program_policies
            .insert(program.program_id.clone(), candidate.clone());
        tx.world
            .identifier_policies
            .insert(policy.id.clone(), policy.clone());
        let receipt = claim_receipt(
            &policy.id, &candidate, &resolver, uaid, &owner, 0, None, b"value",
        );
        let opaque_id = receipt.payload.opaque_id;
        let error = ClaimIdentifier {
            account: owner.clone(),
            receipt,
        }
        .execute(&owner, &mut tx)
        .expect_err("stored active flag cannot admit insecure claim");
        assert!(
            error.to_string().contains("noiseless public-key equation"),
            "{error}"
        );
        assert!(tx.world.identifier_claims.get(&opaque_id).is_none());
        assert!(tx.world.opaque_uaids.get(&opaque_id).is_none());
        assert!(
            !tx.world
                .account(&owner)
                .unwrap()
                .opaque_ids()
                .contains(&opaque_id)
        );
        tx.world
            .ram_lfe_program_policies
            .remove(program.program_id.clone());
    }
}

#[test]
fn identifier_receipt_checks_policy_and_commitment_backends_before_decode() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let policy = email_policy(&owner);
    let mut program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let state = test_state();
    let receipt = claim_receipt(
        &policy.id,
        &program,
        &resolver,
        UniversalAccountId::from_hash(Hash::new(b"uaid")),
        &owner,
        0,
        None,
        b"value",
    );
    for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
        for (policy_backend, commitment_backend) in [
            (backend, RamLfeBackend::HkdfSha3_512PrfV1),
            (RamLfeBackend::HkdfSha3_512PrfV1, backend),
        ] {
            program.backend = policy_backend;
            program.commitment.backend = commitment_backend;
            program.commitment.public_parameters = vec![0xff];
            let error = validate_program_receipt(
                &receipt,
                &policy,
                &program,
                state.network_id_ref(),
                1,
                crate::zk::ZkVerifyGuardrails {
                    pipa_r_enabled: true,
                    pipa_r_max_envelope_bytes: usize::MAX,
                    pipa_r_max_proof_bytes: usize::MAX,

                    stark_enabled: true,
                    stark_max_envelope_bytes: 1,
                    stark_max_proof_bytes: 1,
                },
            )
            .expect_err("both metadata boundaries must refuse before decoding");
            assert!(
                error.to_string().contains("noiseless public-key equation"),
                "{error}"
            );
        }
    }
}

#[test]
fn phone_policy_registration_preserves_exact_shape_and_attestor_requirements() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let state = test_state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1, 0));
    let mut tx = block.transaction();
    for (name, normalization, program) in [
        (
            "phone#other",
            IdentifierNormalization::PhoneE164,
            "phone_retail",
        ),
        (
            "phone#retail",
            IdentifierNormalization::PhoneE164,
            "phone_other",
        ),
        (
            "email#retail",
            IdentifierNormalization::PhoneE164,
            "phone_retail",
        ),
        (
            "email#retail",
            IdentifierNormalization::EmailAddress,
            "phone_retail",
        ),
    ] {
        let policy = IdentifierPolicy::new(
            name.parse().unwrap(),
            owner.clone(),
            normalization,
            program.parse().unwrap(),
        )
        .with_phone_retail_attestor_public_key(resolver.public_key().clone());
        let error = RegisterIdentifierPolicy { policy }
            .execute(&owner, &mut tx)
            .unwrap_err();
        assert!(
            error.to_string().contains("exactly phone#retail"),
            "{error}"
        );
    }
    let bare = IdentifierPolicy::new(
        "phone#retail".parse().unwrap(),
        owner.clone(),
        IdentifierNormalization::PhoneE164,
        "phone_retail".parse().unwrap(),
    );
    let error = RegisterIdentifierPolicy {
        policy: bare.clone(),
    }
    .execute(&owner, &mut tx)
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("explicit pinned canonicality attestor key"),
        "{error}"
    );
    let pinned = bare.with_phone_retail_attestor_public_key(resolver.public_key().clone());
    let program = sample_program_policy(&owner, &resolver, &pinned.program_id);
    tx.world
        .ram_lfe_program_policies
        .insert(program.program_id.clone(), program);
    let error = RegisterIdentifierPolicy {
        policy: pinned.clone(),
    }
    .execute(&owner, &mut tx)
    .unwrap_err();
    assert!(
        error.to_string().contains("noiseless public-key equation"),
        "{error}"
    );
    assert!(tx.world.identifier_policies.get(&pinned.id).is_none());
}

#[test]
fn opening_and_receipt_signatures_bind_the_independent_authorities() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let wrong = checked_keypair();
    let policy = email_policy(&owner);
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let mut receipt = claim_receipt(
        &policy.id,
        &program,
        &resolver,
        UniversalAccountId::from_hash(Hash::new(b"uaid")),
        &owner,
        0,
        None,
        b"value",
    );
    assert_ne!(
        receipt.payload.opening.payload.opened_output_hash,
        receipt.payload.execution.output_ciphertext_hash
    );
    receipt.verify(resolver.public_key()).expect("known signer");
    validate_output_opening(
        &receipt.payload.opening,
        &receipt.payload.execution,
        &program,
    )
    .unwrap();
    receipt.attestation = RamLfeReceiptAttestation::Signed(
        checked_signature_of(wrong.private_key(), &receipt.payload).into(),
    );
    assert!(receipt.verify(resolver.public_key()).is_err());
    receipt.payload.opening.signature =
        checked_signature_of(wrong.private_key(), &receipt.payload.opening.payload).into();
    let error = validate_output_opening(
        &receipt.payload.opening,
        &receipt.payload.execution,
        &program,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("output opening signature is invalid"),
        "{error}"
    );
}

#[test]
fn validly_signed_opening_rejects_each_execution_context_mismatch() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let policy = email_policy(&owner);
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let receipt = claim_receipt(
        &policy.id,
        &program,
        &resolver,
        UniversalAccountId::from_hash(Hash::new(b"uaid")),
        &owner,
        0,
        Some(60_000),
        b"value",
    );
    for index in 0..7 {
        let mut opening = receipt.payload.opening.clone();
        let expected = match index {
            0 => {
                opening.payload.program_id = "other".parse().unwrap();
                "does not match execution program"
            }
            1 => {
                opening.payload.input_ciphertext_hash = Hash::new(b"changed");
                "input ciphertext hash does not match"
            }
            2 => {
                opening.payload.output_ciphertext_hash = Hash::new(b"changed");
                "output ciphertext hash does not match"
            }
            3 => {
                opening.payload.parameter_digest = Hash::new(b"changed");
                "parameter digest does not match"
            }
            4 => {
                opening.payload.evaluation_key_digest = Hash::new(b"changed");
                "evaluation-key digest does not match"
            }
            5 => {
                opening.payload.opened_output_hash = Hash::prehashed([0; Hash::LENGTH]);
                "opening hash must not be zero"
            }
            _ => {
                opening.payload.expires_at_ms = Some(opening.payload.opened_at_ms);
                "opening expiry must be greater"
            }
        };
        opening.signature = checked_signature_of(resolver.private_key(), &opening.payload).into();
        opening
            .verify_signature(resolver.public_key())
            .expect("mutation is validly signed");
        let error =
            validate_output_opening(&opening, &receipt.payload.execution, &program).unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "case {index}: {error}"
        );
    }
}

#[test]
fn canonical_phone_attestation_rejects_missing_context_and_untrusted_signer() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let attestor = checked_keypair();
    let state = test_state();
    let network_id = *state.network_id_ref();
    let policy = IdentifierPolicy::new(
        "phone#retail".parse().unwrap(),
        owner.clone(),
        IdentifierNormalization::PhoneE164,
        "phone_retail".parse().unwrap(),
    )
    .with_phone_retail_attestor_public_key(attestor.public_key().clone());
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let receipt = phone_retail_claim_receipt(
        &policy.id,
        &program,
        &resolver,
        &attestor,
        &network_id,
        UniversalAccountId::from_hash(Hash::new(b"uaid")),
        &owner,
        100,
        60_000,
        "+15551234567",
    );
    let nullifier =
        validate_phone_retail_canonicality(&receipt, &policy, &program, &network_id, 101)
            .unwrap()
            .unwrap();
    let expected =
        expected_identifier_hashes(&policy, &receipt.payload.opening, Some(&nullifier)).unwrap();
    assert_eq!(receipt.payload.opaque_id, OpaqueAccountId::from(expected.0));
    assert_eq!(receipt.payload.receipt_hash, expected.1);
    assert_ne!(
        OpaqueAccountId::from(Hash::new(b"unrelated-phone-opaque-id")),
        OpaqueAccountId::from(expected.0)
    );
    for index in 0..5 {
        let mut changed = receipt.clone();
        let expected = match index {
            0 => {
                changed.phone_retail_canonicality = None;
                "requires a trusted canonical"
            }
            1 => {
                changed
                    .phone_retail_canonicality
                    .as_mut()
                    .unwrap()
                    .payload
                    .network_id = NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign-genesis")),
                );
                "differs from network"
            }
            2 => {
                changed
                    .phone_retail_canonicality
                    .as_mut()
                    .unwrap()
                    .payload
                    .canonical_phone_nullifier = Hash::prehashed([0; Hash::LENGTH]);
                "validity window is invalid"
            }
            3 => {
                changed
                    .phone_retail_canonicality
                    .as_mut()
                    .unwrap()
                    .payload
                    .expires_at_ms = 101;
                "validity window is invalid"
            }
            _ => {
                let evidence = changed.phone_retail_canonicality.as_mut().unwrap();
                evidence.signature =
                    checked_signature_of(resolver.private_key(), &evidence.payload).into();
                "canonicality signature is invalid"
            }
        };
        let error =
            validate_phone_retail_canonicality(&changed, &policy, &program, &network_id, 101)
                .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "case {index}: {error}"
        );
    }
}

#[test]
fn identifier_metadata_rejects_zero_receipt_hash_and_invalid_expiry() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let policy = email_policy(&owner);
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let receipt = claim_receipt(
        &policy.id,
        &program,
        &resolver,
        UniversalAccountId::from_hash(Hash::new(b"uaid")),
        &owner,
        5,
        Some(10),
        b"value",
    );
    validate_identifier_receipt_metadata(&receipt).unwrap();
    let mut zero = receipt.clone();
    zero.payload.receipt_hash = Hash::prehashed([0; Hash::LENGTH]);
    assert!(
        validate_identifier_receipt_metadata(&zero)
            .unwrap_err()
            .to_string()
            .contains("receipt hash must not be zero")
    );
    let mut expired = receipt;
    expired.payload.execution.expires_at_ms = Some(5);
    assert!(
        validate_identifier_receipt_metadata(&expired)
            .unwrap_err()
            .to_string()
            .contains("expiry must be greater")
    );
}

#[test]
fn output_binding_rejects_resigned_opaque_id_and_receipt_hash_changes() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let attestor = checked_keypair();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"output-binding"));
    let state = test_state();
    let network = *state.network_id_ref();
    for phone in [false, true] {
        let policy = if phone {
            IdentifierPolicy::new(
                "phone#retail".parse().unwrap(),
                owner.clone(),
                IdentifierNormalization::PhoneE164,
                "phone_retail".parse().unwrap(),
            )
            .with_phone_retail_attestor_public_key(attestor.public_key().clone())
        } else {
            email_policy(&owner)
        };
        let program = sample_program_policy(&owner, &resolver, &policy.program_id);
        let receipt = if phone {
            phone_claim_receipt(
                &policy.id,
                &program,
                &resolver,
                &attestor,
                network,
                uaid,
                &owner,
                "+15551234567",
                b"ciphertext",
                b"plaintext",
                100,
            )
        } else {
            claim_receipt(
                &policy.id,
                &program,
                &resolver,
                uaid,
                &owner,
                100,
                Some(60_000),
                b"alice@example.com",
            )
        };
        let nullifier =
            validate_phone_retail_canonicality(&receipt, &policy, &program, &network, 101).unwrap();
        validate_identifier_output_binding(&receipt, &policy, nullifier.as_ref()).unwrap();
        for opaque in [false, true] {
            let mut changed = receipt.clone();
            let expected = if opaque {
                changed.payload.opaque_id = OpaqueAccountId::from(Hash::new(b"different-opaque"));
                "opaque_id does not match"
            } else {
                changed.payload.receipt_hash = Hash::new(b"different-receipt");
                "receipt hash does not match"
            };
            changed.attestation = RamLfeReceiptAttestation::Signed(
                checked_signature_of(resolver.private_key(), &changed.payload).into(),
            );
            changed
                .verify(resolver.public_key())
                .expect("changed identifier is correctly signed");
            let error = validate_identifier_output_binding(&changed, &policy, nullifier.as_ref())
                .unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "phone={phone}, opaque={opaque}: {error}"
            );
        }
    }
}

#[test]
fn verified_binding_checks_account_identity_and_lifetime() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid"));
    let policy = email_policy(&owner);
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    for index in 0..7 {
        let mut state = seeded_state(&owner, uaid);
        let mut receipt = claim_receipt(
            &policy.id,
            &program,
            &resolver,
            uaid,
            &owner,
            5,
            Some(20),
            b"value",
        );
        let expected = match index {
            0 => {
                let (key, value) = Account::new(owner.clone()).into_account().into_key_value();
                state.world.accounts.insert(key, value);
                "does not have a UAID"
            }
            1 => {
                receipt.payload.account_id = checked_account_id();
                "does not match claim account"
            }
            2 => {
                receipt.payload.uaid = UniversalAccountId::from_hash(Hash::new(b"other"));
                "does not match account"
            }
            3 => {
                receipt.payload.execution.executed_at_ms = 12;
                "receipt for policy email#retail was issued in the future"
            }
            4 => {
                receipt.payload.opening.payload.opened_at_ms = 12;
                "output opening for policy email#retail was issued in the future"
            }
            5 => {
                receipt.payload.execution.expires_at_ms = Some(10);
                "receipt for policy email#retail expired at or before block time"
            }
            _ => {
                receipt.payload.opening.payload.expires_at_ms = Some(10);
                "output opening for policy email#retail expired at or before block time"
            }
        };
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 11, 0));
        let mut tx = block.transaction();
        let opaque_id = receipt.payload.opaque_id;
        // This unit checks the private state transition after verification. It
        // does not invoke or qualify ClaimIdentifier admission.
        let error = apply_verified_identifier_claim(
            owner.clone(),
            VerifiedIdentifierClaim {
                receipt,
                policy: policy.clone(),
            },
            &mut tx,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "case {index}: {error}"
        );
        assert!(tx.world.identifier_claims.get(&opaque_id).is_none());
        assert!(tx.world.opaque_uaids.get(&opaque_id).is_none());
    }
}

#[test]
fn verified_binding_and_revoke_update_all_indexes_and_enforce_authority() {
    let owner = checked_account_id();
    let resolver = checked_keypair();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid"));
    let state = seeded_state(&owner, uaid);
    let policy = email_policy(&owner);
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let receipt = claim_receipt(
        &policy.id,
        &program,
        &resolver,
        uaid,
        &owner,
        0,
        Some(60_000),
        b"value",
    );
    let opaque_id = receipt.payload.opaque_id;
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1, 0));
    let mut tx = block.transaction();
    RegisterIdentifierPolicy {
        policy: policy.clone(),
    }
    .execute(&owner, &mut tx)
    .unwrap();
    ActivateIdentifierPolicy {
        policy_id: policy.id.clone(),
    }
    .execute(&owner, &mut tx)
    .unwrap();
    apply_verified_identifier_claim(
        owner.clone(),
        VerifiedIdentifierClaim {
            receipt,
            policy: policy.clone(),
        },
        &mut tx,
    )
    .unwrap();
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let claim = state
        .world
        .identifier_claims
        .view()
        .get(&opaque_id)
        .cloned()
        .unwrap();
    assert_eq!(claim.policy_id, policy.id);
    assert_eq!(claim.uaid, uaid);
    assert_eq!(claim.account_id, owner);
    assert_ne!(claim.receipt_hash, Hash::prehashed([0; Hash::LENGTH]));
    assert_eq!(state.world.opaque_uaids.view().get(&opaque_id), Some(&uaid));
    assert!(
        state
            .world
            .accounts
            .view()
            .get(&owner)
            .unwrap()
            .opaque_ids()
            .contains(&opaque_id)
    );
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 2, 0));
    let mut tx = block.transaction();
    let wrong = checked_account_id();
    let revoke = RevokeIdentifier {
        policy_id: policy.id.clone(),
        opaque_id,
    };
    assert!(
        revoke
            .clone()
            .execute(&wrong, &mut tx)
            .unwrap_err()
            .to_string()
            .contains("not allowed")
    );
    revoke.execute(&owner, &mut tx).unwrap();
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    assert!(
        state
            .world
            .identifier_claims
            .view()
            .get(&opaque_id)
            .is_none()
    );
    assert!(state.world.opaque_uaids.view().get(&opaque_id).is_none());
    assert!(
        !state
            .world
            .accounts
            .view()
            .get(&owner)
            .unwrap()
            .opaque_ids()
            .contains(&opaque_id)
    );
}

#[test]
fn expired_binding_replaces_all_indexes_for_the_new_uaid() {
    let owner = checked_account_id();
    let replacement = checked_account_id();
    let resolver = checked_keypair();
    let owner_uaid = UniversalAccountId::from_hash(Hash::new(b"owner"));
    let replacement_uaid = UniversalAccountId::from_hash(Hash::new(b"replacement"));
    let mut state = seeded_state(&owner, owner_uaid);
    seed_account_with_uaid(&mut state, &replacement, replacement_uaid);
    let policy = email_policy(&owner);
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let first = claim_receipt(
        &policy.id,
        &program,
        &resolver,
        owner_uaid,
        &owner,
        0,
        Some(50),
        b"shared",
    );
    let opaque_id = first.payload.opaque_id;
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1, 0));
    let mut tx = block.transaction();
    apply_verified_identifier_claim(
        owner.clone(),
        VerifiedIdentifierClaim {
            receipt: first,
            policy: policy.clone(),
        },
        &mut tx,
    )
    .unwrap();
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 101, 0));
    let mut tx = block.transaction();
    let receipt = claim_receipt(
        &policy.id,
        &program,
        &resolver,
        replacement_uaid,
        &replacement,
        100,
        Some(200),
        b"shared",
    );
    apply_verified_identifier_claim(
        replacement.clone(),
        VerifiedIdentifierClaim { receipt, policy },
        &mut tx,
    )
    .unwrap();
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let claim = state
        .world
        .identifier_claims
        .view()
        .get(&opaque_id)
        .cloned()
        .unwrap();
    assert_eq!(claim.account_id, replacement);
    assert_eq!(claim.uaid, replacement_uaid);
    assert_eq!(claim.expires_at_ms, Some(200));
    assert_eq!(
        state.world.opaque_uaids.view().get(&opaque_id),
        Some(&replacement_uaid)
    );
    assert!(
        !state
            .world
            .accounts
            .view()
            .get(&owner)
            .unwrap()
            .opaque_ids()
            .contains(&opaque_id)
    );
    assert!(
        state
            .world
            .accounts
            .view()
            .get(&replacement)
            .unwrap()
            .opaque_ids()
            .contains(&opaque_id)
    );
}

#[test]
fn phone_nullifier_identity_is_independent_of_ciphertext_and_globally_unique() {
    let owner = checked_account_id();
    let other = checked_account_id();
    let resolver = checked_keypair();
    let attestor = checked_keypair();
    let owner_uaid = UniversalAccountId::from_hash(Hash::new(b"owner"));
    let other_uaid = UniversalAccountId::from_hash(Hash::new(b"other"));
    let mut state = seeded_state(&owner, owner_uaid);
    seed_account_with_uaid(&mut state, &other, other_uaid);
    let network = *state.network_id_ref();
    let policy = IdentifierPolicy::new(
        "phone#retail".parse().unwrap(),
        owner.clone(),
        IdentifierNormalization::PhoneE164,
        "phone_retail".parse().unwrap(),
    )
    .with_phone_retail_attestor_public_key(attestor.public_key().clone());
    let program = sample_program_policy(&owner, &resolver, &policy.program_id);
    let first = phone_claim_receipt(
        &policy.id,
        &program,
        &resolver,
        &attestor,
        network,
        owner_uaid,
        &owner,
        "+15551234567",
        b"ciphertext-one",
        b"output-one",
        100,
    );
    let nullifier =
        validate_phone_retail_canonicality(&first, &policy, &program, &network, 101).unwrap();
    let opaque_id = first.payload.opaque_id;
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 101, 0));
    let mut tx = block.transaction();
    apply_verified_identifier_claim(
        owner,
        VerifiedIdentifierClaim {
            receipt: first,
            policy: policy.clone(),
        },
        &mut tx,
    )
    .unwrap();
    assert_eq!(
        tx.world
            .identifier_claims
            .get(&opaque_id)
            .unwrap()
            .phone_retail_nullifier,
        nullifier
    );
    let second = phone_claim_receipt(
        &policy.id,
        &program,
        &resolver,
        &attestor,
        network,
        other_uaid,
        &other,
        "+15551234567",
        b"ciphertext-two",
        b"output-two",
        100,
    );
    assert_eq!(second.payload.opaque_id, opaque_id);
    assert_eq!(
        validate_phone_retail_canonicality(&second, &policy, &program, &network, 101).unwrap(),
        nullifier
    );
    let error = apply_verified_identifier_claim(
        other.clone(),
        VerifiedIdentifierClaim {
            receipt: second,
            policy: policy.clone(),
        },
        &mut tx,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("already bound to UAID"),
        "{error}"
    );
    let different = phone_claim_receipt(
        &policy.id,
        &program,
        &resolver,
        &attestor,
        network,
        other_uaid,
        &other,
        "+15551234568",
        b"ciphertext-three",
        b"output-three",
        100,
    );
    assert_ne!(different.payload.opaque_id, opaque_id);
    ensure_policy_authorized(&policy.owner, &policy, Some(&other)).unwrap();
    apply_verified_identifier_claim(
        other,
        VerifiedIdentifierClaim {
            receipt: different,
            policy,
        },
        &mut tx,
    )
    .unwrap();
}

// These controls evaluate the real native HKDF primitive under a software DATA
// ledger policy. They establish identifier receipt validation, never wallet authority.
fn current_owner_prf_receipt_fixture_for(
    policy_literal: &str,
    normalization: IdentifierNormalization,
    program_literal: &str,
    normalized_input: &str,
) -> (
    IdentifierPolicy,
    RamLfeProgramPolicy,
    IdentifierResolutionReceipt,
    NetworkId,
    KeyPair,
) {
    let signer = KeyPair::try_from_seed(vec![0x61; 32], Algorithm::Ed25519).unwrap();
    let owner = AccountId::new(
        KeyPair::try_from_seed(vec![0x62; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    let beneficiary = AccountId::new(
        KeyPair::try_from_seed(vec![0x63; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    let network = *test_state().network_id_ref();
    let secret = iroha_crypto::RamLfeSecret::try_from(vec![0x64; 32]).unwrap();
    let commitment = iroha_crypto::policy_commitment(secret.as_ref(), Vec::new()).unwrap();
    let id: RamLfeProgramId = program_literal.parse().unwrap();
    let policy = IdentifierPolicy::new(
        policy_literal.parse().unwrap(),
        owner.clone(),
        normalization,
        id.clone(),
    );
    let program = RamLfeProgramPolicy::new(
        id.clone(),
        owner,
        RamLfeBackend::HkdfSha3_512PrfV1,
        RamLfeVerificationMode::Signed,
        commitment,
        signer.public_key().clone(),
    );
    let request = iroha_crypto::ClientRequest {
        normalized_input: iroha_data_model::identifier::hkdf_identifier_request_payload_v1(
            &network,
            &id,
            normalized_input,
        )
        .unwrap(),
        associated_data: norito::encode_canonical(&id).unwrap(),
    };
    let evaluated = iroha_crypto::evaluate_commitment_with_hidden_program(
        secret.as_ref(),
        &program.commitment,
        &request,
        None,
    )
    .unwrap();
    let output_hash = ram_lfe_output_hash(evaluated.opaque_id.as_ref());
    let input_hash = iroha_data_model::identifier::hkdf_identifier_input_commitment_v1(
        &network,
        &id,
        normalized_input,
        &[0x65; 32],
    )
    .unwrap();
    let (program_digest, parameter_digest, evaluation_key_digest) =
        iroha_data_model::identifier::hkdf_identifier_execution_metadata_v1(&program.commitment)
            .unwrap();
    let execution = RamLfeExecutionReceiptPayload {
        program_id: id.clone(),
        program_digest,
        backend: program.backend,
        verification_mode: program.verification_mode,
        input_ciphertext_hash: input_hash,
        output_ciphertext_hash: output_hash,
        parameter_digest,
        evaluation_key_digest,
        output_hash,
        associated_data_hash: Hash::new(&request.associated_data),
        executed_at_ms: 1_000,
        expires_at_ms: Some(31_000),
    };
    let original = RamLfeOutputOpeningPayload {
        program_id: id,
        input_ciphertext_hash: input_hash,
        output_ciphertext_hash: output_hash,
        parameter_digest,
        evaluation_key_digest,
        opened_output_hash: output_hash,
        opened_at_ms: execution.executed_at_ms,
        expires_at_ms: execution.expires_at_ms,
    };
    let opening = RamLfeOutputOpening {
        signature: checked_signature_of(signer.private_key(), &original).into(),
        payload: original,
    };
    let (opaque, receipt_hash) =
        identifier_hashes_from_output_hash(&request.associated_data, &output_hash);
    let payload = IdentifierResolutionReceiptPayload {
        network_id: network,
        policy_id: policy.id.clone(),
        execution,
        opening,
        opaque_id: OpaqueAccountId::from_hash(opaque),
        receipt_hash,
        uaid: UniversalAccountId::from_hash(Hash::new(b"independent-beneficiary")),
        account_id: beneficiary,
    };
    let receipt = IdentifierResolutionReceipt {
        attestation: RamLfeReceiptAttestation::Signed(
            checked_signature_of(signer.private_key(), &payload).into(),
        ),
        payload,
        phone_retail_canonicality: None,
    };
    (policy, program, receipt, network, signer)
}
fn current_owner_prf_receipt_fixture() -> (
    IdentifierPolicy,
    RamLfeProgramPolicy,
    IdentifierResolutionReceipt,
    NetworkId,
    KeyPair,
) {
    current_owner_prf_receipt_fixture_for(
        "email#retail",
        IdentifierNormalization::EmailAddress,
        "email_retail",
        "alice@example.test",
    )
}
fn current_identifier_guardrails() -> crate::zk::ZkVerifyGuardrails {
    crate::zk::ZkVerifyGuardrails {
        pipa_r_enabled: true,
        pipa_r_max_envelope_bytes: usize::MAX,
        pipa_r_max_proof_bytes: usize::MAX,
        stark_enabled: true,
        stark_max_envelope_bytes: usize::MAX,
        stark_max_proof_bytes: usize::MAX,
    }
}
#[test]
fn current_hkdf_identifier_receipt_binds_network_and_independent_beneficiary() {
    let (policy, program, receipt, network, _) = current_owner_prf_receipt_fixture();
    assert_ne!(policy.owner, receipt.payload.account_id);
    validate_program_receipt(
        &receipt,
        &policy,
        &program,
        &network,
        1_001,
        current_identifier_guardrails(),
    )
    .unwrap();
    let other = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"other-network"),
    ));
    assert!(
        validate_program_receipt(
            &receipt,
            &policy,
            &program,
            &other,
            1_001,
            current_identifier_guardrails()
        )
        .is_err()
    );
}
#[test]
fn current_hkdf_identifier_receipt_rejects_resigned_policy_metadata_and_original_substitutions() {
    let (policy, program, receipt, network, signer) = current_owner_prf_receipt_fixture();
    for mutation in 0..9 {
        let mut changed = receipt.clone();
        match mutation {
            0 => {
                changed.payload.network_id = NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other-network")),
                )
            }
            1 => changed.payload.execution.program_digest = Hash::new(b"other-policy"),
            2 => changed.payload.execution.parameter_digest = Hash::new(b"other-parameters"),
            3 => {
                changed.payload.execution.evaluation_key_digest = Hash::new(b"fake-evaluation-key")
            }
            4 => changed.payload.execution.associated_data_hash = Hash::new(b"other-program"),
            5 => changed.payload.execution.executed_at_ms += 1,
            6 => changed.payload.execution.expires_at_ms = Some(31_001),
            7 => changed.payload.opening.payload.opened_output_hash = Hash::new(b"other-output"),
            _ => changed.payload.opaque_id = OpaqueAccountId::from_hash(Hash::new(b"other-opaque")),
        }
        changed.payload.opening.signature =
            checked_signature_of(signer.private_key(), &changed.payload.opening.payload).into();
        changed.attestation = RamLfeReceiptAttestation::Signed(
            checked_signature_of(signer.private_key(), &changed.payload).into(),
        );
        assert!(
            validate_program_receipt(
                &changed,
                &policy,
                &program,
                &network,
                1_001,
                current_identifier_guardrails()
            )
            .is_err(),
            "mutation {mutation}"
        );
    }
}
#[test]
fn current_hkdf_identifier_receipt_uses_deterministic_block_time_and_original_bounded_lease() {
    let (policy, program, receipt, network, signer) = current_owner_prf_receipt_fixture();
    for now in [0, 999, 31_000, 31_001] {
        assert!(
            validate_program_receipt(
                &receipt,
                &policy,
                &program,
                &network,
                now,
                current_identifier_guardrails()
            )
            .is_err()
        );
    }
    for expiry in [None, Some(1_000), Some(121_001)] {
        let mut changed = receipt.clone();
        changed.payload.opening.payload.expires_at_ms = expiry;
        changed.payload.execution.expires_at_ms = expiry;
        changed.payload.opening.signature =
            checked_signature_of(signer.private_key(), &changed.payload.opening.payload).into();
        changed.attestation = RamLfeReceiptAttestation::Signed(
            checked_signature_of(signer.private_key(), &changed.payload).into(),
        );
        assert!(
            validate_program_receipt(
                &changed,
                &policy,
                &program,
                &network,
                1_001,
                current_identifier_guardrails()
            )
            .is_err()
        );
    }
}
#[test]
fn current_hkdf_identifier_receipt_keeps_resolver_and_opener_signature_pins() {
    let (policy, mut program, receipt, network, _) = current_owner_prf_receipt_fixture();
    let wrong = checked_keypair();
    program.resolver_public_key = wrong.public_key().clone();
    assert!(
        validate_program_receipt(
            &receipt,
            &policy,
            &program,
            &network,
            1_001,
            current_identifier_guardrails()
        )
        .is_err()
    );
    let (_, mut program, receipt, network, _) = current_owner_prf_receipt_fixture();
    program.output_opening_public_key = wrong.public_key().clone();
    assert!(
        validate_program_receipt(
            &receipt,
            &policy,
            &program,
            &network,
            1_001,
            current_identifier_guardrails()
        )
        .is_err()
    );
}

#[test]
fn current_hkdf_phone_identifier_requires_independent_canonicality_and_original_output() {
    let (mut policy, program, mut receipt, network, resolver) =
        current_owner_prf_receipt_fixture_for(
            "phone#retail",
            IdentifierNormalization::PhoneE164,
            "phone_retail",
            "+15551234567",
        );
    let attestor = KeyPair::try_from_seed(vec![0x66; 32], Algorithm::Ed25519).unwrap();
    policy.phone_retail_attestor_public_key = Some(attestor.public_key().clone());
    let original = &receipt.payload.opening.payload;
    let statement = PhoneRetailCanonicalityPayloadV1 {
        network_id: network,
        policy_id: policy.id.clone(),
        program_id: policy.program_id.clone(),
        input_ciphertext_hash: original.input_ciphertext_hash,
        output_ciphertext_hash: original.output_ciphertext_hash,
        opened_output_hash: original.opened_output_hash,
        canonical_phone_nullifier: original.opened_output_hash,
        uaid: receipt.payload.uaid,
        account_id: receipt.payload.account_id.clone(),
        issued_at_ms: original.opened_at_ms,
        expires_at_ms: original.expires_at_ms.unwrap(),
    };
    receipt.phone_retail_canonicality = Some(PhoneRetailCanonicalityAttestationV1 {
        signature: checked_signature_of(attestor.private_key(), &statement).into(),
        payload: statement,
    });
    validate_program_receipt(
        &receipt,
        &policy,
        &program,
        &network,
        1_001,
        current_identifier_guardrails(),
    )
    .unwrap();
    for mutation in 0..5 {
        let mut changed = receipt.clone();
        let evidence = changed.phone_retail_canonicality.as_mut().unwrap();
        match mutation {
            0 => evidence.payload.canonical_phone_nullifier = Hash::new(b"other-phone-output"),
            1 => evidence.payload.issued_at_ms += 1,
            2 => evidence.payload.expires_at_ms += 1,
            3 => evidence.payload.account_id = policy.owner.clone(),
            _ => {
                evidence.payload.network_id = NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other-phone-network")),
                )
            }
        }
        evidence.signature = checked_signature_of(attestor.private_key(), &evidence.payload).into();
        assert!(
            validate_program_receipt(
                &changed,
                &policy,
                &program,
                &network,
                1_001,
                current_identifier_guardrails()
            )
            .is_err(),
            "phone mutation {mutation}"
        );
    }
    policy.phone_retail_attestor_public_key = Some(resolver.public_key().clone());
    assert!(
        validate_program_receipt(
            &receipt,
            &policy,
            &program,
            &network,
            1_001,
            current_identifier_guardrails()
        )
        .is_err()
    );
}

#[test]
fn current_phone_policy_registration_keeps_exact_owner_and_independent_attestor() {
    let (mut policy, program, _, _, resolver) = current_owner_prf_receipt_fixture_for(
        "phone#retail",
        IdentifierNormalization::PhoneE164,
        "phone_retail",
        "+15551234567",
    );
    let attestor = KeyPair::try_from_seed(vec![0x67; 32], Algorithm::Ed25519).unwrap();
    let state = test_state();
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 1_001, 0));
    let mut tx = block.transaction();
    tx.world
        .ram_lfe_program_policies
        .insert(program.program_id.clone(), program.clone());
    policy.phone_retail_attestor_public_key = Some(resolver.public_key().clone());
    assert!(
        validate_phone_retail_policy_registration(&policy, &tx)
            .unwrap_err()
            .to_string()
            .contains("independent")
    );
    policy.phone_retail_attestor_public_key = Some(attestor.public_key().clone());
    validate_phone_retail_policy_registration(&policy, &tx).unwrap();
    let mut changed = program;
    changed.owner = receipt_independent_test_account();
    tx.world
        .ram_lfe_program_policies
        .insert(changed.program_id.clone(), changed);
    assert!(validate_phone_retail_policy_registration(&policy, &tx).is_err());
}
fn receipt_independent_test_account() -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![0x68; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
