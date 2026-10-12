//! Provider-backed phone control: codec, framing, binding of every field, validity
//! boundaries, challenge replay and the provider key lifecycle.
//!
//! This is a separate target so it does not depend on the large internal unit suite.

use iroha_crypto::{
    Algorithm, Hash, HashOf, HiddenRamFheInstruction as Op, HiddenRamFheProgram, KeyPair,
    PHONE_CONTROL_V1_CRYPTO_DOMAINS, PhoneControlError, PhoneControlProviderKeyIdV1,
    PhoneNumberBlindingV1, PhoneNumberCommitmentDigestV1, PhoneNumberCommitmentV1, PhoneNumberV1,
    RAM_LFE_V1_PUBLIC_DOMAINS, RamLfeAssociatedDataHashV1, RamLfeClassV1,
    RamLfeEncryptionKeyCommitmentV1, RamLfeEvaluationKeyCommitmentV1, RamLfeExecutionContextIdV1,
    RamLfeFunctionIdentityV1, RamLfeInitialMemoryV1, RamLfeInitializedMemoryCommitmentV1,
    RamLfeInputCiphertextCommitmentV1, RamLfeOpeningKeyCommitmentV1,
    RamLfeOutputCiphertextCommitmentV1, RamLfePolicyV1, RamLfePrfKeyCommitmentV1,
    RamLfeProfileIdV1, RamLfeProgramKeyV1, RamLfeQueryLimitV1, RamLfeRelationIdV1, Signature,
};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    identifier::{IdentifierNormalization, IdentifierPolicyId},
    phone_control::{
        PHONE_CONTROL_V1_MAX_PROVIDER_KEYS, PHONE_CONTROL_V1_MODEL_DOMAINS,
        PhoneControlAdmissionV1, PhoneControlChallengeIdV1, PhoneControlChallengeV1,
        PhoneControlContextV1, PhoneControlCredentialV1, PhoneControlEvidenceV1,
        PhoneControlProviderKeyStateV1, PhoneControlProviderKeyV1, PhoneControlProviderPolicyV1,
        PhoneControlSignedCredentialV1, phone_control_challenge_prunable,
    },
    ram_lfe::{
        RAM_LFE_V1_MODEL_DOMAINS, RamLfeProgramId, RamLfeReceiptV1, RamLfeReplayDomainV1,
        RamLfeReplayV1,
    },
};
use iroha_schema::IntoSchema;
use std::{collections::BTreeMap, fmt};

const DAY_MS: u64 = 86_400_000;
/// Committed credential lifetime of the fixture policy: thirty days.
const MAX_CREDENTIAL_MS: u64 = 30 * DAY_MS;
/// Committed binding lifetime of the fixture policy: seven days.
const MAX_BINDING_MS: u64 = 7 * DAY_MS;
/// Registration time of the fixture provider keys.
const REGISTERED_AT_MS: u64 = 1_777_000_000_000;
/// Issue time of the fixture credential.
const ISSUED_AT_MS: u64 = 1_777_777_777_000;
/// Expiry of the fixture credential: three days after it was issued.
const EXPIRES_AT_MS: u64 = ISSUED_AT_MS + 3 * DAY_MS;

fn ram_policy(multiplier: u64) -> RamLfePolicyV1 {
    let mut builder = HiddenRamFheProgram::builder().unwrap();
    for instruction in [
        Op::LoadInput(0, 1),
        Op::MulPlain(0, 0, multiplier),
        Op::Output(0),
    ] {
        builder.push(instruction).unwrap();
    }
    RamLfePolicyV1 {
        function: RamLfeFunctionIdentityV1::commit(
            RamLfeClassV1::Affine,
            &RamLfeProgramKeyV1::from_bytes([7; 32]).unwrap(),
            &builder.finish().unwrap(),
            RamLfeQueryLimitV1::new(1000, 3).unwrap(),
        )
        .unwrap(),
        profile: RamLfeProfileIdV1::from_descriptor(b"profile").unwrap(),
        encryption_key: RamLfeEncryptionKeyCommitmentV1::commit(b"encryption").unwrap(),
        evaluation_key: RamLfeEvaluationKeyCommitmentV1::commit(b"evaluation").unwrap(),
        opening_key: RamLfeOpeningKeyCommitmentV1::commit(b"opening").unwrap(),
        prf_key: RamLfePrfKeyCommitmentV1::commit(b"prf").unwrap(),
        relation: RamLfeRelationIdV1::from_descriptor(b"relation").unwrap(),
    }
}

fn network(seed: &[u8]) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        seed,
    )))
}

fn ed25519(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}

fn account(seed: u8) -> AccountId {
    AccountId::new(ed25519(seed).public_key().clone())
}

fn namespace(literal: &str) -> IdentifierPolicyId {
    literal.parse().unwrap()
}

fn key_id(pair: &KeyPair) -> PhoneControlProviderKeyIdV1 {
    PhoneControlProviderKeyIdV1::commit(pair.public_key()).unwrap()
}

fn commitment(number: &[u8], blinding: u8) -> PhoneNumberCommitmentV1 {
    PhoneNumberCommitmentV1::commit(
        PhoneNumberCommitmentDigestV1::GoldilocksDigest384V1,
        &PhoneNumberV1::from_canonical(number).unwrap(),
        &PhoneNumberBlindingV1::from_bytes([blinding; 32]).unwrap(),
    )
}

/// The first provider of the fixture policy.
fn provider() -> KeyPair {
    ed25519(0x11)
}

/// The second provider of the fixture policy.
fn second_provider() -> KeyPair {
    ed25519(0x22)
}

/// A provider policy with the given keys, each active from its registration.
fn provider_policy_with(providers: &[&KeyPair]) -> PhoneControlProviderPolicyV1 {
    let mut policy = PhoneControlProviderPolicyV1::new(
        namespace("phone#retail"),
        MAX_CREDENTIAL_MS,
        MAX_BINDING_MS,
    )
    .unwrap();
    for pair in providers {
        policy
            .register_key(
                pair.public_key().clone(),
                REGISTERED_AT_MS,
                REGISTERED_AT_MS,
            )
            .unwrap();
    }
    policy.validate().unwrap();
    policy
}

fn provider_policy() -> PhoneControlProviderPolicyV1 {
    provider_policy_with(&[&provider(), &second_provider()])
}

fn context() -> PhoneControlContextV1 {
    PhoneControlContextV1 {
        network: network(b"genesis"),
        identifier_policy: namespace("phone#retail"),
        policy: ram_policy(5).commitment().unwrap(),
        beneficiary: account(1),
    }
}

fn challenge() -> PhoneControlChallengeV1 {
    let context = context();
    PhoneControlChallengeV1 {
        provider: key_id(&provider()),
        network: context.network,
        identifier_policy: context.identifier_policy,
        policy: context.policy,
        beneficiary: context.beneficiary,
        number: commitment(b"+15551234567", 0x42),
        client_nonce: [0xC1; 32],
        provider_nonce: [0xB2; 32],
        expires_at_ms: EXPIRES_AT_MS,
    }
}

/// Evidence a provider issues for a challenge record at one instant.
fn issue(
    challenge: &PhoneControlChallengeV1,
    signer: &KeyPair,
    issued_at_ms: u64,
) -> PhoneControlEvidenceV1 {
    PhoneControlEvidenceV1 {
        challenge: challenge.clone(),
        credential: PhoneControlCredentialV1::answering(challenge, issued_at_ms)
            .unwrap()
            .sign(signer)
            .unwrap(),
    }
}

fn evidence() -> PhoneControlEvidenceV1 {
    issue(&challenge(), &provider(), ISSUED_AT_MS)
}

/// Sign a credential as written, without the consistency check of `sign`.
fn sign_raw(
    credential: PhoneControlCredentialV1,
    signer: &KeyPair,
) -> PhoneControlSignedCredentialV1 {
    let signature =
        Signature::try_new(signer.private_key(), &credential.signing_message().unwrap()).unwrap();
    PhoneControlSignedCredentialV1 {
        credential,
        signature,
    }
}

fn admit(evidence: &PhoneControlEvidenceV1) -> Result<PhoneControlAdmissionV1, PhoneControlError> {
    evidence.verify(&provider_policy(), &context(), ISSUED_AT_MS)
}

fn roundtrip<T>(value: &T)
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq + fmt::Debug,
{
    let frame = norito::encode_canonical(value).unwrap();
    assert_eq!(&norito::decode_canonical::<T>(&frame).unwrap(), value);
    assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
}

#[test]
fn every_phone_control_record_roundtrips_through_norito() {
    let mut policy = provider_policy();
    policy
        .retire_key(&key_id(&provider()), ISSUED_AT_MS, REGISTERED_AT_MS)
        .unwrap();
    policy
        .revoke_key(&key_id(&second_provider()), REGISTERED_AT_MS)
        .unwrap();
    // A lowered credential lifetime leaves a nonzero expiry record in the frame.
    policy
        .set_lifetimes(MAX_CREDENTIAL_MS - 1, MAX_BINDING_MS, ISSUED_AT_MS)
        .unwrap();
    assert_ne!(policy.longer_credentials_expire_by_ms, 0);
    roundtrip(&policy);
    roundtrip(&policy.commitment().unwrap());
    for key in &policy.keys {
        roundtrip(key);
        roundtrip(&key.state);
    }
    roundtrip(&PhoneControlProviderKeyStateV1::Active);
    let evidence = evidence();
    roundtrip(&evidence);
    roundtrip(&evidence.challenge);
    roundtrip(&evidence.challenge.id().unwrap());
    roundtrip(&evidence.credential);
    roundtrip(&evidence.credential.credential);
}

#[test]
fn valid_evidence_is_admitted_and_reports_exactly_what_it_established() {
    let evidence = evidence();
    let admission = admit(&evidence).unwrap();
    assert_eq!(admission.network(), &context().network);
    assert_eq!(admission.challenge(), &evidence.challenge.id().unwrap());
    assert_eq!(admission.provider(), &key_id(&provider()));
    assert_eq!(admission.number(), &commitment(b"+15551234567", 0x42));
    assert_eq!(admission.credential_expires_at_ms(), EXPIRES_AT_MS);
    assert_eq!(admission.admitted_at_ms(), ISSUED_AT_MS);
    // The credential lives three days and the committed binding lifetime is
    // seven, so the credential expiry is the earlier bound.
    assert_eq!(admission.binding_expires_at_ms(), EXPIRES_AT_MS);
    // The credential repeats every field it shares with the challenge.
    let credential = &evidence.credential.credential;
    credential.verify_challenge(&evidence.challenge).unwrap();
    assert_eq!(credential.expires_at_ms, evidence.challenge.expires_at_ms);
    assert_eq!(credential.issued_at_ms, ISSUED_AT_MS);
}

#[test]
fn evidence_under_an_mldsa65_provider_key_is_admitted() {
    let pair = KeyPair::try_random_with_algorithm(Algorithm::MlDsa).unwrap();
    let policy = provider_policy_with(&[&pair]);
    let record = PhoneControlChallengeV1 {
        provider: key_id(&pair),
        ..challenge()
    };
    let evidence = issue(&record, &pair, ISSUED_AT_MS);
    evidence.verify(&policy, &context(), ISSUED_AT_MS).unwrap();
    // The same statement signed by an Ed25519 key is not this provider's.
    let forged = PhoneControlEvidenceV1 {
        credential: sign_raw(evidence.credential.credential.clone(), &provider()),
        ..evidence
    };
    assert_eq!(
        forged.verify(&policy, &context(), ISSUED_AT_MS),
        Err(PhoneControlError::BadProviderSignature)
    );
}

#[test]
fn credential_is_bound_to_the_authoritative_context() {
    let evidence = evidence();
    let policy = provider_policy();
    let rejected = |context: PhoneControlContextV1, field: &'static str| {
        assert_eq!(
            evidence.verify(&policy, &context, ISSUED_AT_MS),
            Err(PhoneControlError::ContextMismatch(field))
        );
    };
    rejected(
        PhoneControlContextV1 {
            network: network(b"another genesis"),
            ..context()
        },
        "network",
    );
    rejected(
        PhoneControlContextV1 {
            policy: ram_policy(6).commitment().unwrap(),
            ..context()
        },
        "policy",
    );
    // Rotation of the encryption key changes the complete policy commitment,
    // so a credential issued before the rotation no longer matches.
    let rotated = ram_policy(5).rotate_encryption_keys(
        RamLfeEncryptionKeyCommitmentV1::commit(b"rotated encryption").unwrap(),
        RamLfeEvaluationKeyCommitmentV1::commit(b"rotated evaluation").unwrap(),
        RamLfeOpeningKeyCommitmentV1::commit(b"rotated opening").unwrap(),
    );
    assert_eq!(rotated.function, ram_policy(5).function);
    rejected(
        PhoneControlContextV1 {
            policy: rotated.commitment().unwrap(),
            ..context()
        },
        "policy",
    );
    rejected(
        PhoneControlContextV1 {
            beneficiary: account(2),
            ..context()
        },
        "beneficiary",
    );
    // A claim in another namespace: the provider policy of the first namespace
    // does not govern it, and a policy of the other namespace does not admit a
    // credential made for the first.
    rejected(
        PhoneControlContextV1 {
            identifier_policy: namespace("phone#wholesale"),
            ..context()
        },
        "provider policy namespace",
    );
    let mut other_namespace = provider_policy();
    other_namespace.identifier_policy = namespace("phone#wholesale");
    assert_eq!(
        evidence.verify(
            &other_namespace,
            &PhoneControlContextV1 {
                identifier_policy: namespace("phone#wholesale"),
                ..context()
            },
            ISSUED_AT_MS
        ),
        Err(PhoneControlError::ContextMismatch("identifier policy"))
    );
}

/// One substitution of a bound field, applied to the challenge record, to the
/// credential and to the authoritative context alike, so that only the
/// provider signature still names the original value.
struct Substitution {
    field: &'static str,
    challenge: fn(&mut PhoneControlChallengeV1),
    credential: fn(&mut PhoneControlCredentialV1),
    context: fn(&mut PhoneControlContextV1),
}

fn substitutions() -> Vec<Substitution> {
    fn keep_challenge(_: &mut PhoneControlChallengeV1) {}
    fn keep_credential(_: &mut PhoneControlCredentialV1) {}
    fn keep_context(_: &mut PhoneControlContextV1) {}
    vec![
        Substitution {
            field: "provider",
            challenge: |record| record.provider = key_id(&second_provider()),
            credential: |credential| credential.provider = key_id(&second_provider()),
            context: keep_context,
        },
        Substitution {
            field: "network",
            challenge: |record| record.network = network(b"another genesis"),
            credential: |credential| credential.network = network(b"another genesis"),
            context: |context| context.network = network(b"another genesis"),
        },
        Substitution {
            field: "identifier_policy",
            challenge: |record| record.identifier_policy = namespace("phone#wholesale"),
            credential: |credential| credential.identifier_policy = namespace("phone#wholesale"),
            context: |context| context.identifier_policy = namespace("phone#wholesale"),
        },
        Substitution {
            field: "policy",
            challenge: |record| record.policy = ram_policy(6).commitment().unwrap(),
            credential: |credential| credential.policy = ram_policy(6).commitment().unwrap(),
            context: |context| context.policy = ram_policy(6).commitment().unwrap(),
        },
        Substitution {
            field: "beneficiary",
            challenge: |record| record.beneficiary = account(2),
            credential: |credential| credential.beneficiary = account(2),
            context: |context| context.beneficiary = account(2),
        },
        Substitution {
            field: "challenge (client nonce)",
            challenge: |record| record.client_nonce[31] ^= 1,
            credential: keep_credential,
            context: keep_context,
        },
        Substitution {
            field: "challenge (provider nonce)",
            challenge: |record| record.provider_nonce[0] ^= 1,
            credential: keep_credential,
            context: keep_context,
        },
        Substitution {
            field: "number (another number)",
            challenge: |record| record.number = commitment(b"+15551234568", 0x42),
            credential: |credential| credential.number = commitment(b"+15551234568", 0x42),
            context: keep_context,
        },
        Substitution {
            field: "number (another blinding)",
            challenge: |record| record.number = commitment(b"+15551234567", 0x43),
            credential: |credential| credential.number = commitment(b"+15551234567", 0x43),
            context: keep_context,
        },
        Substitution {
            field: "issued_at_ms",
            challenge: keep_challenge,
            credential: |credential| credential.issued_at_ms += 1,
            context: keep_context,
        },
        Substitution {
            field: "expires_at_ms",
            challenge: |record| record.expires_at_ms += 1,
            credential: |credential| credential.expires_at_ms += 1,
            context: keep_context,
        },
    ]
}

#[test]
fn provider_signature_binds_every_field_of_the_credential() {
    let original = evidence();
    admit(&original).unwrap();
    let substitutions = substitutions();
    // Every field of the signed frame is substituted at least once.
    let covered: Vec<&str> = substitutions
        .iter()
        .map(|substitution| substitution.field.split(' ').next().unwrap())
        .collect();
    for field in schema_fields::<PhoneControlCredentialV1>() {
        assert!(
            covered.contains(&field.as_str()),
            "{field} is not substituted"
        );
    }

    for substitution in substitutions {
        let mut record = original.challenge.clone();
        (substitution.challenge)(&mut record);
        let mut credential = original.credential.credential.clone();
        (substitution.credential)(&mut credential);
        // The substituted credential names the substituted challenge record.
        credential.challenge = record.id().unwrap();
        credential.verify_challenge(&record).unwrap();
        let mut context = context();
        (substitution.context)(&mut context);
        let mut policy = provider_policy();
        policy.identifier_policy = context.identifier_policy.clone();
        assert_ne!(
            credential, original.credential.credential,
            "{} must change the signed frame",
            substitution.field
        );

        // Everything a validator compares agrees with the substituted value.
        // Only the signature is the provider's signature over the original.
        let forged = PhoneControlEvidenceV1 {
            challenge: record.clone(),
            credential: PhoneControlSignedCredentialV1 {
                credential: credential.clone(),
                signature: original.credential.signature.clone(),
            },
        };
        assert_eq!(
            forged.verify(&policy, &context, ISSUED_AT_MS + 1),
            Err(PhoneControlError::BadProviderSignature),
            "{}",
            substitution.field
        );

        // Control: the same substituted statement is admitted once the named
        // provider really signs it, so the rejection above is the signature.
        let signer = if credential.provider == key_id(&provider()) {
            provider()
        } else {
            second_provider()
        };
        let honest = PhoneControlEvidenceV1 {
            challenge: record,
            credential: sign_raw(credential, &signer),
        };
        honest
            .verify(&policy, &context, ISSUED_AT_MS + 1)
            .unwrap_or_else(|error| panic!("{}: {error}", substitution.field));
    }
}

#[test]
fn provider_signature_is_over_the_documented_message() {
    let evidence = evidence();
    let credential = &evidence.credential.credential;
    let frame = norito::encode_canonical(credential).unwrap();
    let message = credential.signing_message().unwrap();
    assert_eq!(
        message,
        [
            b"iroha.ram_lfe.v1.phone_control.credential".as_slice(),
            &frame
        ]
        .concat()
    );
    evidence
        .credential
        .signature
        .verify(provider().public_key(), &message)
        .unwrap();
    // The bare frame, the frame under another domain of this contract and a
    // digest of the message are not what the provider signed.
    for other in [
        frame.clone(),
        [
            b"iroha.ram_lfe.v1.phone_control.challenge".as_slice(),
            &frame,
        ]
        .concat(),
        Hash::new(&message).as_ref().to_vec(),
    ] {
        assert!(
            evidence
                .credential
                .signature
                .verify(provider().public_key(), &other)
                .is_err()
        );
    }
    // The challenge identity is the documented commitment to its record.
    let record = norito::encode_canonical(&evidence.challenge).unwrap();
    assert_eq!(
        evidence.challenge.id().unwrap().as_hash(),
        &Hash::new(
            [
                b"iroha.ram_lfe.v1.phone_control.challenge".as_slice(),
                &record
            ]
            .concat()
        )
    );
}

#[test]
fn signing_refuses_a_key_the_credential_does_not_name() {
    let credential = PhoneControlCredentialV1::answering(&challenge(), ISSUED_AT_MS).unwrap();
    assert_eq!(
        credential.clone().sign(&second_provider()).unwrap_err(),
        PhoneControlError::ContextMismatch("provider key")
    );
    let unsupported = KeyPair::try_from_seed(vec![9; 32], Algorithm::Secp256k1).unwrap();
    assert_eq!(
        credential.clone().sign(&unsupported).unwrap_err(),
        PhoneControlError::UnsupportedProviderKeyAlgorithm
    );
    credential.sign(&provider()).unwrap();
}

/// One change of a credential before the provider signs it.
type AlterCredential = fn(&mut PhoneControlCredentialV1);

#[test]
fn credential_must_answer_the_presented_challenge() {
    let original = evidence();
    // A challenge record that differs in any field has another identity.
    let altered: [fn(&mut PhoneControlChallengeV1); 9] = [
        |record| record.provider = key_id(&second_provider()),
        |record| record.network = network(b"another genesis"),
        |record| record.identifier_policy = namespace("phone#wholesale"),
        |record| record.policy = ram_policy(6).commitment().unwrap(),
        |record| record.beneficiary = account(2),
        |record| record.number = commitment(b"+15551234567", 0x43),
        |record| record.client_nonce[0] ^= 1,
        |record| record.provider_nonce[31] ^= 1,
        |record| record.expires_at_ms -= 1,
    ];
    assert_eq!(
        altered.len(),
        schema_fields::<PhoneControlChallengeV1>().len()
    );
    for alter in altered {
        let mut record = original.challenge.clone();
        alter(&mut record);
        assert_ne!(record.id().unwrap(), original.challenge.id().unwrap());
        let presented = PhoneControlEvidenceV1 {
            challenge: record,
            credential: original.credential.clone(),
        };
        assert_eq!(
            admit(&presented),
            Err(PhoneControlError::ChallengeMismatch("challenge identity"))
        );
    }

    // A provider that signs a credential whose own fields disagree with the
    // challenge record it names is refused field by field, although the
    // signature and the challenge identity are genuine.
    let disagreeing: [(&str, AlterCredential); 7] = [
        ("provider key", |credential| {
            credential.provider = key_id(&second_provider());
        }),
        ("network", |credential| {
            credential.network = network(b"another genesis");
        }),
        ("identifier policy", |credential| {
            credential.identifier_policy = namespace("phone#wholesale");
        }),
        ("policy", |credential| {
            credential.policy = ram_policy(6).commitment().unwrap();
        }),
        ("beneficiary", |credential| {
            credential.beneficiary = account(2);
        }),
        ("number commitment", |credential| {
            credential.number = commitment(b"+15551234567", 0x43);
        }),
        ("expiry", |credential| credential.expires_at_ms += DAY_MS),
    ];
    for (field, alter) in disagreeing {
        let mut credential = original.credential.credential.clone();
        alter(&mut credential);
        let signer = if credential.provider == key_id(&provider()) {
            provider()
        } else {
            second_provider()
        };
        let presented = PhoneControlEvidenceV1 {
            challenge: original.challenge.clone(),
            credential: sign_raw(credential.clone(), &signer),
        };
        assert_eq!(
            presented
                .credential
                .credential
                .verify_challenge(&presented.challenge),
            Err(PhoneControlError::ChallengeMismatch(field))
        );
        // The context follows the credential, so only the challenge disagrees.
        let context = PhoneControlContextV1 {
            network: credential.network,
            identifier_policy: credential.identifier_policy.clone(),
            policy: credential.policy,
            beneficiary: credential.beneficiary.clone(),
        };
        let mut policy = provider_policy();
        policy.identifier_policy = credential.identifier_policy.clone();
        assert_eq!(
            presented.verify(&policy, &context, ISSUED_AT_MS),
            Err(PhoneControlError::ChallengeMismatch(field))
        );
    }
}

#[test]
fn credential_is_valid_at_the_last_admissible_instant_and_rejected_one_unit_after() {
    let evidence = evidence();
    let at = |now_ms: u64| evidence.verify(&provider_policy(), &context(), now_ms);
    // Lower boundary: the issue time is the first admissible instant.
    assert_eq!(at(ISSUED_AT_MS - 1), Err(PhoneControlError::NotYetValid));
    assert_eq!(at(0), Err(PhoneControlError::NotYetValid));
    at(ISSUED_AT_MS).unwrap();
    at(ISSUED_AT_MS + 1).unwrap();
    // Upper boundary: the expiry is exclusive.
    at(EXPIRES_AT_MS - 1).unwrap();
    assert_eq!(at(EXPIRES_AT_MS), Err(PhoneControlError::Expired));
    assert_eq!(at(EXPIRES_AT_MS + 1), Err(PhoneControlError::Expired));
    assert_eq!(at(u64::MAX), Err(PhoneControlError::Expired));

    // The shortest interval holds exactly one admissible instant.
    let record = PhoneControlChallengeV1 {
        expires_at_ms: ISSUED_AT_MS + 1,
        ..challenge()
    };
    let shortest = issue(&record, &provider(), ISSUED_AT_MS);
    shortest
        .verify(&provider_policy(), &context(), ISSUED_AT_MS)
        .unwrap();
    assert_eq!(
        shortest.verify(&provider_policy(), &context(), ISSUED_AT_MS + 1),
        Err(PhoneControlError::Expired)
    );
}

#[test]
fn credential_lifetime_is_nonempty_and_bounded_by_the_committed_policy() {
    let with_expiry = |expires_at_ms: u64| {
        let record = PhoneControlChallengeV1 {
            expires_at_ms,
            ..challenge()
        };
        issue(&record, &provider(), ISSUED_AT_MS).verify(
            &provider_policy(),
            &context(),
            ISSUED_AT_MS,
        )
    };
    // Exactly the committed maximum is admitted, one millisecond more is not.
    with_expiry(ISSUED_AT_MS + MAX_CREDENTIAL_MS).unwrap();
    assert_eq!(
        with_expiry(ISSUED_AT_MS + MAX_CREDENTIAL_MS + 1),
        Err(PhoneControlError::LifetimeExceeded {
            limit_ms: MAX_CREDENTIAL_MS
        })
    );
    assert_eq!(
        with_expiry(u64::MAX),
        Err(PhoneControlError::LifetimeExceeded {
            limit_ms: MAX_CREDENTIAL_MS
        })
    );
    // An empty and an inverted interval admit no instant.
    assert_eq!(
        with_expiry(ISSUED_AT_MS),
        Err(PhoneControlError::EmptyValidity)
    );
    assert_eq!(
        with_expiry(ISSUED_AT_MS - 1),
        Err(PhoneControlError::EmptyValidity)
    );
    assert_eq!(with_expiry(0), Err(PhoneControlError::EmptyValidity));

    // A tighter committed maximum refuses the fixture credential.
    let mut tight = provider_policy();
    tight
        .set_lifetimes(3 * DAY_MS, DAY_MS, REGISTERED_AT_MS)
        .unwrap();
    evidence().verify(&tight, &context(), ISSUED_AT_MS).unwrap();
    tight
        .set_lifetimes(3 * DAY_MS - 1, DAY_MS, REGISTERED_AT_MS)
        .unwrap();
    assert_eq!(
        evidence().verify(&tight, &context(), ISSUED_AT_MS),
        Err(PhoneControlError::LifetimeExceeded {
            limit_ms: 3 * DAY_MS - 1
        })
    );
}

#[test]
fn binding_never_outlives_its_credential_and_takes_the_earliest_bound() {
    // The credential lives three days and the binding lifetime is seven: the
    // credential expiry bounds the binding.
    let admission = admit(&evidence()).unwrap();
    assert_eq!(admission.binding_expires_at_ms(), EXPIRES_AT_MS);

    // The credential lives thirty days and the binding lifetime is seven: the
    // committed binding lifetime bounds the binding, counted from the issue
    // time and not from the admission time.
    let record = PhoneControlChallengeV1 {
        expires_at_ms: ISSUED_AT_MS + MAX_CREDENTIAL_MS,
        ..challenge()
    };
    let long = issue(&record, &provider(), ISSUED_AT_MS);
    for now_ms in [
        ISSUED_AT_MS,
        ISSUED_AT_MS + 6 * DAY_MS,
        ISSUED_AT_MS + MAX_BINDING_MS - 1,
    ] {
        let admission = long.verify(&provider_policy(), &context(), now_ms).unwrap();
        assert_eq!(
            admission.binding_expires_at_ms(),
            ISSUED_AT_MS + MAX_BINDING_MS
        );
        assert_eq!(
            admission.credential_expires_at_ms(),
            ISSUED_AT_MS + MAX_CREDENTIAL_MS
        );
        assert_eq!(admission.admitted_at_ms(), now_ms);
        assert!(admission.binding_expires_at_ms() > admission.admitted_at_ms());
    }
    // A binding must end strictly after its admission. From the instant the
    // binding lifetime has run, the credential admits nothing, although its
    // own interval is still open for twenty-three days.
    for now_ms in [
        ISSUED_AT_MS + MAX_BINDING_MS,
        ISSUED_AT_MS + MAX_BINDING_MS + 1,
        ISSUED_AT_MS + MAX_CREDENTIAL_MS - 1,
    ] {
        assert_eq!(
            long.verify(&provider_policy(), &context(), now_ms),
            Err(PhoneControlError::BindingExpired)
        );
    }
    assert_eq!(
        long.verify(
            &provider_policy(),
            &context(),
            ISSUED_AT_MS + MAX_CREDENTIAL_MS
        ),
        Err(PhoneControlError::Expired)
    );

    // An issue time so late that the binding lifetime overflows leaves the
    // credential expiry as the bound.
    let late = PhoneControlChallengeV1 {
        expires_at_ms: u64::MAX - 1,
        ..challenge()
    };
    let admission = issue(&late, &provider(), u64::MAX - 5)
        .verify(&provider_policy(), &context(), u64::MAX - 2)
        .unwrap();
    assert_eq!(admission.binding_expires_at_ms(), u64::MAX - 1);

    // The earliest applicable bound wins. No other bound extends the binding.
    let admission = admit(&evidence()).unwrap();
    assert_eq!(admission.earliest_expiry_ms(&[]), Ok(EXPIRES_AT_MS));
    assert_eq!(
        admission.earliest_expiry_ms(&[EXPIRES_AT_MS + 1, u64::MAX]),
        Ok(EXPIRES_AT_MS)
    );
    assert_eq!(
        admission.earliest_expiry_ms(&[EXPIRES_AT_MS + 1, EXPIRES_AT_MS - 1, u64::MAX]),
        Ok(EXPIRES_AT_MS - 1)
    );
    assert_eq!(
        admission.earliest_expiry_ms(&[ISSUED_AT_MS + 5, ISSUED_AT_MS + 4]),
        Ok(ISSUED_AT_MS + 4)
    );
    // The result is strictly after the admission time: a bound one
    // millisecond later gives a binding, a bound at or before it gives none.
    assert_eq!(admission.admitted_at_ms(), ISSUED_AT_MS);
    assert_eq!(
        admission.earliest_expiry_ms(&[ISSUED_AT_MS + 1]),
        Ok(ISSUED_AT_MS + 1)
    );
    for bound_ms in [ISSUED_AT_MS, ISSUED_AT_MS - 1, 0] {
        assert_eq!(
            admission.earliest_expiry_ms(&[EXPIRES_AT_MS, bound_ms]),
            Err(PhoneControlError::BindingExpired)
        );
    }
}

/// The consumed challenges of committed State: (network, challenge) -> expiry.
type ConsumedChallenges = BTreeMap<(NetworkId, PhoneControlChallengeIdV1), u64>;

/// One claim: verify the evidence, then consume its challenge in the same step.
///
/// State forgets every entry it may forget before the claim, which is the
/// least it can remember.
fn claim(
    consumed: &mut ConsumedChallenges,
    evidence: &PhoneControlEvidenceV1,
    now_ms: u64,
) -> Result<u64, PhoneControlError> {
    consumed.retain(|_, recorded_ms| !phone_control_challenge_prunable(*recorded_ms, now_ms));
    let admission = evidence.verify(&provider_policy(), &context(), now_ms)?;
    let key = (*admission.network(), *admission.challenge());
    let expiry = admission.consume_challenge(consumed.get(&key).copied())?;
    consumed.insert(key, expiry);
    Ok(expiry)
}

#[test]
fn challenge_is_consumed_once_and_pruning_cannot_readmit_it() {
    let mut consumed = ConsumedChallenges::new();
    let evidence = evidence();

    // The first claim consumes the challenge and records the credential expiry.
    assert_eq!(
        claim(&mut consumed, &evidence, ISSUED_AT_MS),
        Ok(EXPIRES_AT_MS)
    );
    // The same evidence again, at once and at the last admissible instant.
    assert_eq!(
        claim(&mut consumed, &evidence, ISSUED_AT_MS),
        Err(PhoneControlError::ChallengeReplayed)
    );
    assert_eq!(
        claim(&mut consumed, &evidence, EXPIRES_AT_MS - 1),
        Err(PhoneControlError::ChallengeReplayed)
    );
    // A second credential the provider signs for the same challenge record is
    // the same challenge.
    let reissued = issue(&evidence.challenge, &provider(), ISSUED_AT_MS + 60_000);
    assert_ne!(reissued.credential, evidence.credential);
    assert_eq!(
        claim(&mut consumed, &reissued, ISSUED_AT_MS + 60_000),
        Err(PhoneControlError::ChallengeReplayed)
    );
    // A fresh challenge for the same number and account is another challenge.
    let fresh = PhoneControlChallengeV1 {
        provider_nonce: [0xB3; 32],
        ..challenge()
    };
    assert_eq!(
        claim(
            &mut consumed,
            &issue(&fresh, &provider(), ISSUED_AT_MS),
            ISSUED_AT_MS
        ),
        Ok(EXPIRES_AT_MS)
    );
    assert_eq!(consumed.len(), 2);

    // State may forget the entry from the recorded expiry on, and not before.
    assert!(!phone_control_challenge_prunable(
        EXPIRES_AT_MS,
        EXPIRES_AT_MS - 1
    ));
    assert!(phone_control_challenge_prunable(
        EXPIRES_AT_MS,
        EXPIRES_AT_MS
    ));
    assert!(phone_control_challenge_prunable(
        EXPIRES_AT_MS,
        EXPIRES_AT_MS + 1
    ));

    // After pruning, the credential is expired, so the forgotten entry is not
    // needed to reject it.
    consumed.clear();
    assert_eq!(
        evidence.verify(&provider_policy(), &context(), EXPIRES_AT_MS),
        Err(PhoneControlError::Expired)
    );
    assert_eq!(
        reissued.verify(&provider_policy(), &context(), EXPIRES_AT_MS),
        Err(PhoneControlError::Expired)
    );
    // The same challenge cannot return with a later expiry: the expiry is part
    // of the challenge identity. A credential that names the pruned challenge
    // and extends its own expiry does not answer it, even when the provider
    // really signed it.
    let mut extended = evidence.credential.credential.clone();
    extended.issued_at_ms = EXPIRES_AT_MS;
    extended.expires_at_ms = EXPIRES_AT_MS + DAY_MS;
    let extended = PhoneControlEvidenceV1 {
        challenge: evidence.challenge.clone(),
        credential: sign_raw(extended, &provider()),
    };
    assert_eq!(
        extended.verify(&provider_policy(), &context(), EXPIRES_AT_MS),
        Err(PhoneControlError::ChallengeMismatch("expiry"))
    );
    // Extending the record as well gives another challenge identity, which is
    // a new challenge and not a replay of the pruned one.
    let later = PhoneControlChallengeV1 {
        expires_at_ms: EXPIRES_AT_MS + DAY_MS,
        ..challenge()
    };
    assert_ne!(later.id().unwrap(), evidence.challenge.id().unwrap());

    // The entry is recorded with the expiry of the credential, not with the
    // bound of the binding. The fixture credential cannot tell the two apart,
    // so take one that lives thirty days while its binding lives seven.
    let mut consumed = ConsumedChallenges::new();
    let long_record = PhoneControlChallengeV1 {
        provider_nonce: [0xB4; 32],
        expires_at_ms: ISSUED_AT_MS + MAX_CREDENTIAL_MS,
        ..challenge()
    };
    let long = issue(&long_record, &provider(), ISSUED_AT_MS);
    let admission = long
        .verify(&provider_policy(), &context(), ISSUED_AT_MS)
        .unwrap();
    let binding_bound_ms = ISSUED_AT_MS + MAX_BINDING_MS;
    let credential_expiry_ms = ISSUED_AT_MS + MAX_CREDENTIAL_MS;
    assert_eq!(admission.binding_expires_at_ms(), binding_bound_ms);
    assert_eq!(admission.consume_challenge(None), Ok(credential_expiry_ms));
    assert_eq!(
        admission.consume_challenge(Some(credential_expiry_ms)),
        Err(PhoneControlError::ChallengeReplayed)
    );
    assert_eq!(
        claim(&mut consumed, &long, ISSUED_AT_MS),
        Ok(credential_expiry_ms)
    );
    // When the first binding has run out, the provider signs a second
    // credential for the same challenge record. Its interval and its binding
    // bound are open, so nothing but the consumed entry rejects it.
    let second = issue(&long_record, &provider(), binding_bound_ms);
    second
        .verify(&provider_policy(), &context(), binding_bound_ms)
        .unwrap();
    assert!(!phone_control_challenge_prunable(
        credential_expiry_ms,
        binding_bound_ms
    ));
    // An entry recorded with the bound of the binding could be forgotten at
    // this instant, and the second credential would then be admitted.
    assert!(phone_control_challenge_prunable(
        binding_bound_ms,
        binding_bound_ms
    ));
    assert_eq!(
        claim(&mut consumed, &second, binding_bound_ms),
        Err(PhoneControlError::ChallengeReplayed)
    );
    // The entry is kept through the last instant at which any credential for
    // the challenge is admissible, and may be forgotten at the next.
    let last = issue(&long_record, &provider(), credential_expiry_ms - 1);
    last.verify(&provider_policy(), &context(), credential_expiry_ms - 1)
        .unwrap();
    assert_eq!(
        claim(&mut consumed, &last, credential_expiry_ms - 1),
        Err(PhoneControlError::ChallengeReplayed)
    );
    assert_eq!(consumed.len(), 1);
    assert_eq!(
        claim(&mut consumed, &last, credential_expiry_ms),
        Err(PhoneControlError::Expired)
    );
    assert!(consumed.is_empty());

    // Evidence that fails verification yields no admission, so a rejected
    // claim has nothing to consume.
    let rejected = PhoneControlEvidenceV1 {
        credential: PhoneControlSignedCredentialV1 {
            signature: Signature::from_bytes(&[1; 64]),
            ..evidence.credential.clone()
        },
        ..evidence
    };
    assert!(admit(&rejected).is_err());
}

#[test]
fn rotated_provider_key_issues_nothing_from_its_retirement_on() {
    let retired_from_ms = ISSUED_AT_MS + DAY_MS;
    let mut policy = provider_policy();
    policy
        .retire_key(&key_id(&provider()), retired_from_ms, ISSUED_AT_MS)
        .unwrap();
    let issued_at = |issued_at_ms: u64, now_ms: u64| {
        let record = PhoneControlChallengeV1 {
            expires_at_ms: issued_at_ms + DAY_MS,
            ..challenge()
        };
        issue(&record, &provider(), issued_at_ms).verify(&policy, &context(), now_ms)
    };
    // The last instant before retirement still issues, and that credential
    // stays admissible after the retirement until it expires.
    issued_at(retired_from_ms - 1, retired_from_ms - 1).unwrap();
    issued_at(retired_from_ms - 1, retired_from_ms).unwrap();
    issued_at(retired_from_ms - 1, retired_from_ms + DAY_MS - 2).unwrap();
    assert_eq!(
        issued_at(retired_from_ms - 1, retired_from_ms + DAY_MS - 1),
        Err(PhoneControlError::Expired)
    );
    // From the retirement on the key issues nothing.
    assert_eq!(
        issued_at(retired_from_ms, retired_from_ms),
        Err(PhoneControlError::ProviderKeyRetired)
    );
    assert_eq!(
        issued_at(retired_from_ms + 1, retired_from_ms + 1),
        Err(PhoneControlError::ProviderKeyRetired)
    );
    // Retirement ends no binding.
    let retired = policy.key(&key_id(&provider())).unwrap();
    for admitted_at_ms in [0, retired_from_ms - 1, retired_from_ms, u64::MAX] {
        assert!(!retired.evicts_binding(admitted_at_ms));
    }

    // The replacement key issues from its own activation on, and not before.
    let replacement = second_provider();
    let record = |issued_at_ms: u64| PhoneControlChallengeV1 {
        provider: key_id(&replacement),
        expires_at_ms: issued_at_ms + DAY_MS,
        ..challenge()
    };
    issue(&record(retired_from_ms), &replacement, retired_from_ms)
        .verify(&policy, &context(), retired_from_ms)
        .unwrap();
    issue(&record(REGISTERED_AT_MS), &replacement, REGISTERED_AT_MS)
        .verify(&policy, &context(), REGISTERED_AT_MS)
        .unwrap();
    assert_eq!(
        issue(
            &record(REGISTERED_AT_MS - 1),
            &replacement,
            REGISTERED_AT_MS - 1
        )
        .verify(&policy, &context(), REGISTERED_AT_MS),
        Err(PhoneControlError::ProviderKeyNotActive)
    );
}

#[test]
fn revoked_provider_key_admits_no_credential_and_evicts_by_ledger_time() {
    let compromised_from_ms = ISSUED_AT_MS + DAY_MS;
    let mut policy = provider_policy();
    let evidence = evidence();
    // Admissible before the revocation.
    evidence.verify(&policy, &context(), ISSUED_AT_MS).unwrap();
    policy
        .revoke_key(&key_id(&provider()), compromised_from_ms)
        .unwrap();
    // Every credential under the key is refused, whatever its issue time: the
    // one issued before the cutoff too, because the key can backdate.
    for now_ms in [ISSUED_AT_MS, compromised_from_ms - 1, compromised_from_ms] {
        assert_eq!(
            evidence.verify(&policy, &context(), now_ms),
            Err(PhoneControlError::ProviderKeyRevoked)
        );
    }
    for issued_at_ms in [
        REGISTERED_AT_MS,
        compromised_from_ms - 1,
        compromised_from_ms,
        compromised_from_ms + 1,
    ] {
        let record = PhoneControlChallengeV1 {
            expires_at_ms: issued_at_ms + DAY_MS,
            ..challenge()
        };
        assert_eq!(
            issue(&record, &provider(), issued_at_ms).verify(&policy, &context(), issued_at_ms),
            Err(PhoneControlError::ProviderKeyRevoked)
        );
    }

    // Eviction uses the ledger time at which the supporting credential was
    // admitted: from the cutoff on, and not before it.
    let revoked = policy.key(&key_id(&provider())).unwrap();
    assert!(!revoked.evicts_binding(0));
    assert!(!revoked.evicts_binding(compromised_from_ms - 1));
    assert!(revoked.evicts_binding(compromised_from_ms));
    assert!(revoked.evicts_binding(u64::MAX));
    // The activation time is kept in the revoked state.
    assert_eq!(revoked.active_from_ms, REGISTERED_AT_MS);

    // The other provider is unaffected.
    let other = policy.key(&key_id(&second_provider())).unwrap();
    assert!(!other.evicts_binding(u64::MAX));
    let record = PhoneControlChallengeV1 {
        provider: key_id(&second_provider()),
        ..challenge()
    };
    issue(&record, &second_provider(), ISSUED_AT_MS)
        .verify(&policy, &context(), ISSUED_AT_MS)
        .unwrap();

    // A retired key that is later found compromised is revoked too, and its
    // credentials issued before the retirement are refused from then on.
    let mut policy = provider_policy();
    policy
        .retire_key(&key_id(&provider()), ISSUED_AT_MS + 1, ISSUED_AT_MS)
        .unwrap();
    evidence.verify(&policy, &context(), ISSUED_AT_MS).unwrap();
    policy
        .revoke_key(&key_id(&provider()), REGISTERED_AT_MS)
        .unwrap();
    assert_eq!(
        evidence.verify(&policy, &context(), ISSUED_AT_MS),
        Err(PhoneControlError::ProviderKeyRevoked)
    );
}

#[test]
fn credential_of_an_unregistered_provider_is_refused() {
    let stranger = ed25519(0x33);
    let record = PhoneControlChallengeV1 {
        provider: key_id(&stranger),
        ..challenge()
    };
    assert_eq!(
        admit(&issue(&record, &stranger, ISSUED_AT_MS)),
        Err(PhoneControlError::UnknownProviderKey)
    );
    // A stranger that names a registered key cannot produce its signature.
    let impersonated = PhoneControlEvidenceV1 {
        challenge: challenge(),
        credential: sign_raw(
            PhoneControlCredentialV1::answering(&challenge(), ISSUED_AT_MS).unwrap(),
            &stranger,
        ),
    };
    assert_eq!(
        admit(&impersonated),
        Err(PhoneControlError::BadProviderSignature)
    );
    // A policy without keys admits nothing.
    assert_eq!(
        evidence().verify(&provider_policy_with(&[]), &context(), ISSUED_AT_MS),
        Err(PhoneControlError::UnknownProviderKey)
    );
}

#[test]
fn provider_key_transitions_only_narrow_what_is_admitted() {
    let transition =
        |message: &'static str| PhoneControlError::InvalidProviderKeyTransition(message);
    let first = key_id(&provider());
    let mut policy = provider_policy_with(&[&provider()]);

    // Registration: a key is trusted from its registration on, once.
    let late = ed25519(0x44);
    assert_eq!(
        policy.register_key(late.public_key().clone(), ISSUED_AT_MS - 1, ISSUED_AT_MS),
        Err(transition(
            "a key cannot become active before it is registered"
        ))
    );
    assert_eq!(
        policy.register_key(provider().public_key().clone(), u64::MAX, ISSUED_AT_MS),
        Err(PhoneControlError::DuplicateProviderKey)
    );
    let unsupported = KeyPair::try_from_seed(vec![9; 32], Algorithm::Secp256k1).unwrap();
    assert_eq!(
        policy.register_key(unsupported.public_key().clone(), ISSUED_AT_MS, ISSUED_AT_MS),
        Err(PhoneControlError::UnsupportedProviderKeyAlgorithm)
    );
    assert_eq!(policy.keys.len(), 1);
    // A key may be scheduled: it issues nothing before its activation.
    let scheduled = policy
        .register_key(
            late.public_key().clone(),
            ISSUED_AT_MS + DAY_MS,
            ISSUED_AT_MS,
        )
        .unwrap();
    assert_eq!(scheduled, key_id(&late));
    assert_eq!(
        policy
            .key(&scheduled)
            .unwrap()
            .verify_issuance(ISSUED_AT_MS + DAY_MS - 1),
        Err(PhoneControlError::ProviderKeyNotActive)
    );
    policy
        .key(&scheduled)
        .unwrap()
        .verify_issuance(ISSUED_AT_MS + DAY_MS)
        .unwrap();
    policy.validate().unwrap();

    // Retirement: from activation on, never backdated, and afterwards only
    // earlier.
    assert_eq!(
        policy.retire_key(&first, REGISTERED_AT_MS - 1, 0),
        Err(transition("a key cannot retire before it becomes active"))
    );
    assert_eq!(
        policy.retire_key(&key_id(&ed25519(0x55)), ISSUED_AT_MS, ISSUED_AT_MS),
        Err(PhoneControlError::UnknownProviderKey)
    );
    // The transition time bounds the retirement from below: the consensus
    // time of the transition is accepted, one millisecond earlier is not.
    let now_ms = ISSUED_AT_MS;
    for backdated in [now_ms - 1, now_ms - DAY_MS, REGISTERED_AT_MS] {
        assert_eq!(
            policy.retire_key(&first, backdated, now_ms),
            Err(transition("a retirement is never backdated"))
        );
    }
    assert_eq!(
        policy.key(&first).unwrap().state,
        PhoneControlProviderKeyStateV1::Active
    );
    policy.clone().retire_key(&first, now_ms, now_ms).unwrap();
    // A retirement may be scheduled, and a scheduled one may move earlier,
    // but never below the time of the transition that moves it.
    policy.retire_key(&first, now_ms + DAY_MS, now_ms).unwrap();
    for not_earlier in [now_ms + DAY_MS, now_ms + DAY_MS + 1, u64::MAX] {
        assert_eq!(
            policy.retire_key(&first, not_earlier, now_ms),
            Err(transition("a retired key may only retire earlier"))
        );
    }
    assert_eq!(
        policy.retire_key(&first, now_ms - 1, now_ms),
        Err(transition("a retirement is never backdated"))
    );
    policy.retire_key(&first, now_ms + 3, now_ms).unwrap();
    // One millisecond later the lowest instant has moved with the time.
    assert_eq!(
        policy.retire_key(&first, now_ms, now_ms + 1),
        Err(transition("a retirement is never backdated"))
    );
    policy.retire_key(&first, now_ms + 1, now_ms + 1).unwrap();
    assert_eq!(
        policy.key(&first).unwrap().state,
        PhoneControlProviderKeyStateV1::Retired {
            retired_from_ms: now_ms + 1
        }
    );
    // A retirement whose instant has arrived is final: an earlier instant
    // would be backdated and no other instant is earlier.
    for (transition_ms, retired_from_ms, refusal) in [
        (now_ms + 1, now_ms, "a retirement is never backdated"),
        (
            now_ms + 1,
            now_ms + 1,
            "a retired key may only retire earlier",
        ),
        (now_ms + 2, now_ms, "a retirement is never backdated"),
        (now_ms + 2, now_ms + 1, "a retirement is never backdated"),
        (
            now_ms + 2,
            now_ms + 2,
            "a retired key may only retire earlier",
        ),
        (
            now_ms + 2,
            u64::MAX,
            "a retired key may only retire earlier",
        ),
    ] {
        assert_eq!(
            policy.retire_key(&first, retired_from_ms, transition_ms),
            Err(transition(refusal))
        );
    }
    policy.key(&first).unwrap().verify_issuance(now_ms).unwrap();
    assert_eq!(
        policy.key(&first).unwrap().verify_issuance(now_ms + 1),
        Err(PhoneControlError::ProviderKeyRetired)
    );
    // A scheduled key cannot retire before its activation. Retired at its
    // activation, which only a transition at or before that instant can
    // record, it never issues anything.
    let activation_ms = ISSUED_AT_MS + DAY_MS;
    assert_eq!(
        policy.retire_key(&scheduled, activation_ms - 1, now_ms),
        Err(transition("a key cannot retire before it becomes active"))
    );
    assert_eq!(
        policy.retire_key(&scheduled, activation_ms, activation_ms + 1),
        Err(transition("a retirement is never backdated"))
    );
    policy
        .retire_key(&scheduled, activation_ms, activation_ms)
        .unwrap();
    for issued_at_ms in [activation_ms - 1, activation_ms, activation_ms + 1] {
        assert!(
            policy
                .key(&scheduled)
                .unwrap()
                .verify_issuance(issued_at_ms)
                .is_err()
        );
    }

    // Revocation: terminal, and its cutoff only moves earlier.
    policy.revoke_key(&first, ISSUED_AT_MS).unwrap();
    for not_earlier in [ISSUED_AT_MS, ISSUED_AT_MS + 1] {
        assert_eq!(
            policy.revoke_key(&first, not_earlier),
            Err(transition("a revoked key may only move its cutoff earlier"))
        );
    }
    policy.revoke_key(&first, 0).unwrap();
    assert_eq!(
        policy.key(&first).unwrap().state,
        PhoneControlProviderKeyStateV1::Revoked {
            compromised_from_ms: 0
        }
    );
    for (retired_from_ms, now_ms) in [
        (ISSUED_AT_MS, ISSUED_AT_MS),
        (u64::MAX, ISSUED_AT_MS),
        (REGISTERED_AT_MS - 1, ISSUED_AT_MS),
    ] {
        assert_eq!(
            policy.retire_key(&first, retired_from_ms, now_ms),
            Err(transition("revocation is terminal"))
        );
    }
    assert_eq!(
        policy.remove_retired_key(&first, u64::MAX),
        Err(transition("only a retired key is removed"))
    );
    // The revoked identity can never be registered again.
    assert_eq!(
        policy.register_key(provider().public_key().clone(), u64::MAX, u64::MAX),
        Err(PhoneControlError::DuplicateProviderKey)
    );
    assert_eq!(
        policy.revoke_key(&key_id(&ed25519(0x55)), 0),
        Err(PhoneControlError::UnknownProviderKey)
    );
    policy.validate().unwrap();
}

#[test]
fn retired_key_is_removed_only_when_nothing_can_depend_on_it() {
    let transition =
        |message: &'static str| PhoneControlError::InvalidProviderKeyTransition(message);
    let first = key_id(&provider());
    let mut policy = provider_policy();
    // An active key is not removed.
    assert_eq!(
        policy.remove_retired_key(&first, u64::MAX),
        Err(transition("only a retired key is removed"))
    );
    // The longest admission window: a binding may live as long as its credential.
    policy
        .set_lifetimes(MAX_CREDENTIAL_MS, MAX_CREDENTIAL_MS, REGISTERED_AT_MS)
        .unwrap();
    assert_eq!(policy.longer_credentials_expire_by_ms, 0);
    let retired_from_ms = ISSUED_AT_MS + DAY_MS;
    policy
        .retire_key(&first, retired_from_ms, ISSUED_AT_MS)
        .unwrap();
    // The last credential the key could issue after the retiring transition
    // expires before retirement + credential lifetime; the record stays until
    // then.
    let removable_from_ms = retired_from_ms + MAX_CREDENTIAL_MS;
    assert_eq!(
        policy.remove_retired_key(&first, removable_from_ms - 1),
        Err(transition(
            "a credential of the retired key may still be live"
        ))
    );
    let record = PhoneControlChallengeV1 {
        expires_at_ms: retired_from_ms - 1 + MAX_CREDENTIAL_MS,
        ..challenge()
    };
    let last = issue(&record, &provider(), retired_from_ms - 1);
    last.verify(&policy, &context(), removable_from_ms - 2)
        .unwrap();
    assert_eq!(
        last.verify(&policy, &context(), removable_from_ms - 1),
        Err(PhoneControlError::Expired)
    );
    policy
        .remove_retired_key(&first, removable_from_ms)
        .unwrap();
    assert_eq!(
        policy.key(&first),
        Err(PhoneControlError::UnknownProviderKey)
    );
    assert_eq!(policy.keys.len(), 1);
    policy.validate().unwrap();
    // The freed identity can be registered again, trusted from then on only.
    policy
        .register_key(
            provider().public_key().clone(),
            removable_from_ms,
            removable_from_ms,
        )
        .unwrap();
    assert_eq!(
        last.verify(&policy, &context(), removable_from_ms),
        Err(PhoneControlError::ProviderKeyNotActive)
    );

    // A retirement so late that the instant overflows never frees the slot.
    let mut policy = provider_policy();
    policy
        .retire_key(&first, u64::MAX - 1, REGISTERED_AT_MS)
        .unwrap();
    assert_eq!(
        policy.remove_retired_key(&first, u64::MAX),
        Err(transition(
            "a credential of the retired key may still be live"
        ))
    );

    // The tightest history: a credential issued and admitted at the instant
    // of the retiring transition, ahead of it in the same block, lives to
    // exactly the removal instant. Its expiry is exclusive, so the binding
    // is over there and one millisecond earlier it is not.
    let mut policy = provider_policy();
    policy
        .set_lifetimes(MAX_CREDENTIAL_MS, MAX_CREDENTIAL_MS, REGISTERED_AT_MS)
        .unwrap();
    let record = PhoneControlChallengeV1 {
        expires_at_ms: ISSUED_AT_MS + MAX_CREDENTIAL_MS,
        ..challenge()
    };
    let latest = issue(&record, &provider(), ISSUED_AT_MS);
    let admission = latest.verify(&policy, &context(), ISSUED_AT_MS).unwrap();
    policy
        .retire_key(&first, ISSUED_AT_MS, ISSUED_AT_MS)
        .unwrap();
    let removable_from_ms = ISSUED_AT_MS + MAX_CREDENTIAL_MS;
    assert_eq!(admission.credential_expires_at_ms(), removable_from_ms);
    assert_eq!(admission.binding_expires_at_ms(), removable_from_ms);
    // The key issues nothing from the retirement on, so the same credential
    // is not admitted a second time. The binding it supports stays.
    assert_eq!(
        latest.verify(&policy, &context(), ISSUED_AT_MS),
        Err(PhoneControlError::ProviderKeyRetired)
    );
    assert_eq!(
        policy.remove_retired_key(&first, removable_from_ms - 1),
        Err(transition(
            "a credential of the retired key may still be live"
        ))
    );
    policy
        .remove_retired_key(&first, removable_from_ms)
        .unwrap();
}

#[test]
fn backdated_retirement_cannot_free_the_key_of_a_live_binding() {
    let transition =
        |message: &'static str| PhoneControlError::InvalidProviderKeyTransition(message);
    let backdated = Err(transition("a retirement is never backdated"));
    let live = Err(transition(
        "a credential of the retired key may still be live",
    ));
    let first = key_id(&provider());

    // One transition. A credential was admitted one day ago and its binding
    // has six days left. A retirement recorded at the registration of the
    // key would put the removal instant, thirty days later, at this moment.
    let mut policy = provider_policy();
    let now_ms = REGISTERED_AT_MS + MAX_CREDENTIAL_MS;
    let issued_at_ms = now_ms - DAY_MS;
    let record = PhoneControlChallengeV1 {
        expires_at_ms: issued_at_ms + MAX_CREDENTIAL_MS,
        ..challenge()
    };
    let supporting = issue(&record, &provider(), issued_at_ms);
    let admission = supporting
        .verify(&policy, &context(), issued_at_ms)
        .unwrap();
    assert_eq!(
        admission.binding_expires_at_ms(),
        now_ms + MAX_BINDING_MS - DAY_MS
    );
    for retired_from_ms in [REGISTERED_AT_MS, issued_at_ms, now_ms - 1] {
        assert_eq!(
            policy.retire_key(&first, retired_from_ms, now_ms),
            backdated
        );
    }
    assert_eq!(
        policy.remove_retired_key(&first, now_ms),
        Err(transition("only a retired key is removed"))
    );
    // The earliest retirement the transition can record is its own time, and
    // the record then outlives the credential and the binding.
    policy.retire_key(&first, now_ms, now_ms).unwrap();
    let removable_from_ms = now_ms + MAX_CREDENTIAL_MS;
    assert!(removable_from_ms > admission.credential_expires_at_ms());
    for attempt_ms in [
        now_ms,
        admission.binding_expires_at_ms() - 1,
        admission.binding_expires_at_ms(),
        admission.credential_expires_at_ms(),
        removable_from_ms - 1,
    ] {
        assert_eq!(policy.remove_retired_key(&first, attempt_ms), live);
    }
    // While the binding is live the record exists, so the key can be revoked
    // and the binding evicted.
    let mut revoked = policy.clone();
    revoked.revoke_key(&first, issued_at_ms).unwrap();
    assert!(
        revoked
            .key(&first)
            .unwrap()
            .evicts_binding(admission.admitted_at_ms())
    );
    policy
        .remove_retired_key(&first, removable_from_ms)
        .unwrap();

    // Two transitions. The key is scheduled to retire, a credential is
    // admitted before that instant, and the owner then moves the retirement
    // earlier. It cannot move behind the admission.
    let mut policy = provider_policy();
    let scheduled_at_ms = ISSUED_AT_MS;
    policy
        .retire_key(&first, scheduled_at_ms + 40 * DAY_MS, scheduled_at_ms)
        .unwrap();
    let issued_at_ms = scheduled_at_ms + 35 * DAY_MS;
    let record = PhoneControlChallengeV1 {
        expires_at_ms: issued_at_ms + MAX_CREDENTIAL_MS,
        ..challenge()
    };
    let supporting = issue(&record, &provider(), issued_at_ms);
    let admission = supporting
        .verify(&policy, &context(), issued_at_ms)
        .unwrap();
    let now_ms = issued_at_ms + DAY_MS;
    for retired_from_ms in [scheduled_at_ms + DAY_MS, issued_at_ms, now_ms - 1] {
        assert_eq!(
            policy.retire_key(&first, retired_from_ms, now_ms),
            backdated
        );
    }
    policy.retire_key(&first, now_ms, now_ms).unwrap();
    assert!(now_ms + MAX_CREDENTIAL_MS > admission.credential_expires_at_ms());
    assert_eq!(
        policy.remove_retired_key(&first, admission.credential_expires_at_ms()),
        live
    );
    policy
        .remove_retired_key(&first, now_ms + MAX_CREDENTIAL_MS)
        .unwrap();
}

#[test]
fn lifetime_change_never_shortens_the_wait_for_earlier_credentials() {
    let invalid = |message: &'static str| Err(PhoneControlError::InvalidProviderPolicy(message));
    let live = Err(PhoneControlError::InvalidProviderKeyTransition(
        "a credential of the retired key may still be live",
    ));
    let first = key_id(&provider());
    let mut policy = provider_policy();

    // The shape rules of registration apply, and a rejected change leaves the
    // policy as it was.
    let unchanged = policy.clone();
    assert_eq!(
        policy.set_lifetimes(0, 1, ISSUED_AT_MS),
        invalid("credential lifetime must not be zero")
    );
    assert_eq!(
        policy.set_lifetimes(1, 0, ISSUED_AT_MS),
        invalid("binding lifetime must not be zero")
    );
    assert_eq!(
        policy.set_lifetimes(DAY_MS, DAY_MS + 1, ISSUED_AT_MS),
        invalid("binding lifetime exceeds the credential lifetime")
    );
    // A lowering so late that the earlier credentials have no expiry instant.
    assert_eq!(
        policy.set_lifetimes(
            MAX_CREDENTIAL_MS - 1,
            MAX_BINDING_MS,
            u64::MAX - MAX_CREDENTIAL_MS + 1
        ),
        invalid("lowering the credential lifetime overflows the time range")
    );
    assert_eq!(policy, unchanged);
    let mut latest = policy.clone();
    latest
        .set_lifetimes(
            MAX_CREDENTIAL_MS - 1,
            MAX_BINDING_MS,
            u64::MAX - MAX_CREDENTIAL_MS,
        )
        .unwrap();
    assert_eq!(latest.longer_credentials_expire_by_ms, u64::MAX);

    // The same values, a raised lifetime and any binding lifetime record
    // nothing, at any time.
    for (credential_ms, binding_ms) in [
        (MAX_CREDENTIAL_MS, MAX_BINDING_MS),
        (MAX_CREDENTIAL_MS, MAX_BINDING_MS - 1),
        (MAX_CREDENTIAL_MS, MAX_CREDENTIAL_MS),
        (MAX_CREDENTIAL_MS + 1, 1),
        (u64::MAX, u64::MAX),
    ] {
        let mut changed = policy.clone();
        changed
            .set_lifetimes(credential_ms, binding_ms, u64::MAX)
            .unwrap();
        assert_eq!(changed.longer_credentials_expire_by_ms, 0);
        assert_eq!(changed.max_credential_lifetime_ms, credential_ms);
        assert_eq!(changed.max_binding_lifetime_ms, binding_ms);
        assert_eq!(changed.keys, policy.keys);
        changed.validate().unwrap();
    }

    // A credential is admitted under the thirty-day lifetime with a binding
    // as long. One day later the owner lowers the lifetime to one day and
    // retires the key.
    policy
        .set_lifetimes(MAX_CREDENTIAL_MS, MAX_CREDENTIAL_MS, REGISTERED_AT_MS)
        .unwrap();
    let record = PhoneControlChallengeV1 {
        expires_at_ms: ISSUED_AT_MS + MAX_CREDENTIAL_MS,
        ..challenge()
    };
    let long = issue(&record, &provider(), ISSUED_AT_MS);
    let admission = long.verify(&policy, &context(), ISSUED_AT_MS).unwrap();
    assert_eq!(
        admission.binding_expires_at_ms(),
        ISSUED_AT_MS + MAX_CREDENTIAL_MS
    );
    let lowered_at_ms = ISSUED_AT_MS + DAY_MS;
    policy.set_lifetimes(DAY_MS, DAY_MS, lowered_at_ms).unwrap();
    let expire_by_ms = lowered_at_ms + MAX_CREDENTIAL_MS;
    assert_eq!(policy.longer_credentials_expire_by_ms, expire_by_ms);
    assert!(expire_by_ms >= admission.credential_expires_at_ms());
    // The new bound applies to every later admission.
    assert_eq!(
        long.verify(&policy, &context(), lowered_at_ms),
        Err(PhoneControlError::LifetimeExceeded { limit_ms: DAY_MS })
    );
    policy
        .retire_key(&first, lowered_at_ms, lowered_at_ms)
        .unwrap();
    // The current lifetime alone would free the record one day after the
    // retirement, twenty-eight days before the binding ends.
    let by_current_lifetime_ms = lowered_at_ms + DAY_MS;
    assert!(by_current_lifetime_ms < admission.binding_expires_at_ms());
    for attempt_ms in [
        by_current_lifetime_ms,
        admission.binding_expires_at_ms() - 1,
        expire_by_ms - 1,
    ] {
        assert_eq!(policy.remove_retired_key(&first, attempt_ms), live);
    }
    let mut revoked = policy.clone();
    revoked.revoke_key(&first, ISSUED_AT_MS).unwrap();
    assert!(
        revoked
            .key(&first)
            .unwrap()
            .evicts_binding(admission.admitted_at_ms())
    );
    policy
        .clone()
        .remove_retired_key(&first, expire_by_ms)
        .unwrap();

    // The record keeps the latest instant over every lowering. A raise in
    // between changes nothing.
    policy
        .set_lifetimes(DAY_MS / 2, DAY_MS / 2, lowered_at_ms + 1)
        .unwrap();
    assert_eq!(policy.longer_credentials_expire_by_ms, expire_by_ms);
    policy
        .set_lifetimes(2 * MAX_CREDENTIAL_MS, DAY_MS, lowered_at_ms + 2)
        .unwrap();
    assert_eq!(policy.longer_credentials_expire_by_ms, expire_by_ms);
    policy
        .set_lifetimes(MAX_CREDENTIAL_MS, DAY_MS, lowered_at_ms + 3)
        .unwrap();
    assert_eq!(
        policy.longer_credentials_expire_by_ms,
        lowered_at_ms + 3 + 2 * MAX_CREDENTIAL_MS
    );

    // When the retirement gives the later instant, the retirement decides.
    let mut policy = provider_policy();
    policy
        .set_lifetimes(DAY_MS, DAY_MS, REGISTERED_AT_MS)
        .unwrap();
    let expire_by_ms = REGISTERED_AT_MS + MAX_CREDENTIAL_MS;
    assert_eq!(policy.longer_credentials_expire_by_ms, expire_by_ms);
    policy
        .retire_key(&first, expire_by_ms, ISSUED_AT_MS)
        .unwrap();
    assert_eq!(
        policy.remove_retired_key(&first, expire_by_ms + DAY_MS - 1),
        live
    );
    policy
        .remove_retired_key(&first, expire_by_ms + DAY_MS)
        .unwrap();
}

/// One step of a short ledger history over one provider key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HistoryStep {
    /// A claim presents a credential issued at `issued_at_ms` that lives
    /// `lifetime_ms`.
    Admit { issued_at_ms: u64, lifetime_ms: u64 },
    /// The owner retires the key from `retired_from_ms`.
    Retire { retired_from_ms: u64 },
    /// The owner sets both lifetimes to `lifetime_ms`.
    SetLifetimes { lifetime_ms: u64 },
}

/// The policy after one step, and the expiry of the credential it admitted.
type HistoryOutcome = (PhoneControlProviderPolicyV1, Option<u64>);

/// Evaluates steps of short histories with the rules under test and
/// remembers each distinct evaluation, so that a large enumeration costs one
/// evaluation for each distinct state.
struct HistoryOracle {
    key: PhoneControlProviderKeyIdV1,
    first_ms: u64,
    last_ms: u64,
    evidence: BTreeMap<(u64, u64), PhoneControlEvidenceV1>,
    outcomes: BTreeMap<PhoneControlProviderPolicyV1, BTreeMap<(u64, HistoryStep), HistoryOutcome>>,
    removable: BTreeMap<PhoneControlProviderPolicyV1, Vec<u64>>,
}

impl HistoryOracle {
    fn new(first_ms: u64, last_ms: u64) -> Self {
        Self {
            key: key_id(&provider()),
            first_ms,
            last_ms,
            evidence: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            removable: BTreeMap::new(),
        }
    }

    /// A policy with one key, registered and active at the first instant.
    fn policy(&self, lifetime_ms: u64) -> PhoneControlProviderPolicyV1 {
        let mut policy =
            PhoneControlProviderPolicyV1::new(namespace("phone#retail"), lifetime_ms, lifetime_ms)
                .unwrap();
        policy
            .register_key(
                provider().public_key().clone(),
                self.first_ms,
                self.first_ms,
            )
            .unwrap();
        policy
    }

    fn evaluate(
        &mut self,
        policy: &PhoneControlProviderPolicyV1,
        now_ms: u64,
        step: HistoryStep,
    ) -> HistoryOutcome {
        let mut next = policy.clone();
        match step {
            HistoryStep::Admit {
                issued_at_ms,
                lifetime_ms,
            } => {
                let evidence = self
                    .evidence
                    .entry((issued_at_ms, lifetime_ms))
                    .or_insert_with(|| {
                        let record = PhoneControlChallengeV1 {
                            expires_at_ms: issued_at_ms + lifetime_ms,
                            ..challenge()
                        };
                        issue(&record, &provider(), issued_at_ms)
                    });
                // The observed range ends after every expiry, so a premature
                // removal cannot lie beyond it.
                let last_ms = self.last_ms;
                let admitted = evidence
                    .verify(policy, &context(), now_ms)
                    .ok()
                    .map(|admission| {
                        let expires_at_ms = admission.credential_expires_at_ms();
                        assert!(admission.binding_expires_at_ms() <= expires_at_ms);
                        assert!(expires_at_ms < last_ms);
                        expires_at_ms
                    });
                (next, admitted)
            }
            HistoryStep::Retire { retired_from_ms } => {
                let accepted = next.retire_key(&self.key, retired_from_ms, now_ms).is_ok();
                assert!(!accepted || retired_from_ms >= now_ms);
                assert!(accepted || next == *policy);
                (next, None)
            }
            HistoryStep::SetLifetimes { lifetime_ms } => {
                let accepted = next.set_lifetimes(lifetime_ms, lifetime_ms, now_ms).is_ok();
                assert!(accepted || next == *policy);
                (next, None)
            }
        }
    }

    /// Apply one step at `now_ms`.
    fn apply(
        &mut self,
        policy: &PhoneControlProviderPolicyV1,
        now_ms: u64,
        step: HistoryStep,
    ) -> HistoryOutcome {
        if let Some(outcome) = self
            .outcomes
            .get(policy)
            .and_then(|outcomes| outcomes.get(&(now_ms, step)))
        {
            return outcome.clone();
        }
        let outcome = self.evaluate(policy, now_ms, step);
        self.outcomes
            .entry(policy.clone())
            .or_default()
            .insert((now_ms, step), outcome.clone());
        outcome
    }

    /// Every instant of the observed range at which the key can be removed.
    fn removable_at(&mut self, policy: &PhoneControlProviderPolicyV1) -> Vec<u64> {
        if let Some(instants) = self.removable.get(policy) {
            return instants.clone();
        }
        let instants: Vec<u64> = (self.first_ms..=self.last_ms)
            .filter(|now_ms| {
                policy
                    .clone()
                    .remove_retired_key(&self.key, *now_ms)
                    .is_ok()
            })
            .collect();
        self.removable.insert(policy.clone(), instants.clone());
        instants
    }
}

/// What an enumeration of histories met, to show that it is not vacuous.
#[derive(Debug, Default, PartialEq, Eq)]
struct HistoryCoverage {
    histories: usize,
    /// Histories in which a credential was admitted.
    admitted: usize,
    /// Removal instants met after an admission.
    removals: usize,
    /// Removal instants that equal the expiry of an admitted credential.
    tight: usize,
}

/// The first instant from `now_ms` on at which the key can be removed while a
/// credential admitted under it is still live, with the expiry of that
/// credential.
fn premature_removal(removable: &[u64], expiries: &[u64], now_ms: u64) -> Option<(u64, u64)> {
    removable
        .iter()
        .filter(|removed_at_ms| **removed_at_ms >= now_ms)
        .find_map(|removed_at_ms| {
            expiries
                .iter()
                .find(|expires_at_ms| *expires_at_ms > removed_at_ms)
                .map(|expires_at_ms| (*removed_at_ms, *expires_at_ms))
        })
}

/// Run one history. After every step, the key must not be removable at any
/// later instant at which a credential admitted under it is still live.
fn run_history(
    oracle: &mut HistoryOracle,
    initial: &PhoneControlProviderPolicyV1,
    history: &[(u64, HistoryStep)],
    coverage: &mut HistoryCoverage,
) -> Result<(), String> {
    let mut policy = initial.clone();
    let mut expiries: Vec<u64> = Vec::new();
    coverage.histories += 1;
    for &(now_ms, step) in history {
        let (next, admitted) = oracle.apply(&policy, now_ms, step);
        policy = next;
        coverage.admitted += usize::from(admitted.is_some());
        expiries.extend(admitted);
        let removable = oracle.removable_at(&policy);
        if let Some((removed_at_ms, expires_at_ms)) =
            premature_removal(&removable, &expiries, now_ms)
        {
            return Err(format!(
                "{history:?}: the key is removable at {removed_at_ms} while a credential \
                 admitted under it lives to {expires_at_ms}"
            ));
        }
        for removed_at_ms in removable.iter().filter(|at_ms| **at_ms >= now_ms) {
            coverage.removals += expiries.len();
            coverage.tight += usize::from(expiries.contains(removed_at_ms));
        }
    }
    Ok(())
}

/// Every order of `steps`.
fn orders(steps: &[HistoryStep]) -> Vec<Vec<HistoryStep>> {
    if steps.len() <= 1 {
        return vec![steps.to_vec()];
    }
    let mut all = Vec::new();
    for (index, first) in steps.iter().enumerate() {
        let mut rest = steps.to_vec();
        rest.remove(index);
        for mut order in orders(&rest) {
            order.insert(0, *first);
            all.push(order);
        }
    }
    all
}

/// Every non-decreasing sequence of `length` instants from `first_ms` to
/// `first_ms + instants - 1`: consensus time never decreases, and steps of
/// one block share an instant.
fn schedules(length: usize, first_ms: u64, instants: u64) -> Vec<Vec<u64>> {
    let mut all = vec![Vec::new()];
    for _ in 0..length {
        all = all
            .into_iter()
            .flat_map(|schedule: Vec<u64>| {
                let from_ms = schedule.last().copied().unwrap_or(first_ms);
                (from_ms..first_ms + instants).map(move |now_ms| {
                    let mut longer = schedule.clone();
                    longer.push(now_ms);
                    longer
                })
            })
            .collect();
    }
    all
}

/// Run `steps` in every order at every schedule.
fn run_every_history(
    oracle: &mut HistoryOracle,
    initial: &PhoneControlProviderPolicyV1,
    steps: &[HistoryStep],
    instants: u64,
    coverage: &mut HistoryCoverage,
) {
    let schedules = schedules(steps.len(), oracle.first_ms, instants);
    for order in orders(steps) {
        for schedule in &schedules {
            let history: Vec<(u64, HistoryStep)> = schedule
                .iter()
                .copied()
                .zip(order.iter().copied())
                .collect();
            if let Err(violation) = run_history(oracle, initial, &history, coverage) {
                panic!("{violation}");
            }
        }
    }
}

#[test]
fn no_transition_sequence_removes_a_key_before_its_credentials_expire() {
    // Time runs in single milliseconds from `FIRST_MS`. Lifetimes are one to
    // three milliseconds, so every boundary of the rules lies inside the range.
    const FIRST_MS: u64 = 1_000;
    let mut oracle = HistoryOracle::new(FIRST_MS, FIRST_MS + 12);
    let mut coverage = HistoryCoverage::default();
    let lifetimes = 1..=3_u64;

    // The check has teeth. A retirement recorded behind the admission of a
    // live credential, which no transition records and which is written into
    // the record directly here, makes the key removable while the credential
    // is live, and the check reports it.
    let mut written = oracle.policy(2);
    written.keys[0].state = PhoneControlProviderKeyStateV1::Retired {
        retired_from_ms: FIRST_MS,
    };
    written.validate().unwrap();
    let admit_late = HistoryStep::Admit {
        issued_at_ms: FIRST_MS + 2,
        lifetime_ms: 2,
    };
    let active = oracle.policy(2);
    assert_eq!(
        oracle.apply(&active, FIRST_MS + 2, admit_late).1,
        Some(FIRST_MS + 4)
    );
    let removable = oracle.removable_at(&written);
    assert_eq!(
        premature_removal(&removable, &[FIRST_MS + 4], FIRST_MS + 2),
        Some((FIRST_MS + 2, FIRST_MS + 4))
    );
    assert_eq!(
        premature_removal(&removable, &[FIRST_MS + 4], FIRST_MS + 4),
        None
    );
    assert_eq!(
        premature_removal(&removable, &[FIRST_MS + 2], FIRST_MS),
        None
    );
    // The transitions refuse to record that state.
    let retire_behind = HistoryStep::Retire {
        retired_from_ms: FIRST_MS,
    };
    assert_eq!(oracle.apply(&active, FIRST_MS + 2, retire_behind).0, active);

    // Retirement, scheduled or immediate, and a second retirement that moves
    // it, around one admission. Lifetimes stay as registered.
    let initial = oracle.policy(2);
    for issued_at_ms in FIRST_MS..FIRST_MS + 4 {
        for lifetime_ms in lifetimes.clone() {
            for first_retirement_ms in FIRST_MS..=FIRST_MS + 5 {
                for second_retirement_ms in FIRST_MS..=FIRST_MS + 5 {
                    run_every_history(
                        &mut oracle,
                        &initial,
                        &[
                            HistoryStep::Admit {
                                issued_at_ms,
                                lifetime_ms,
                            },
                            HistoryStep::Retire {
                                retired_from_ms: first_retirement_ms,
                            },
                            HistoryStep::Retire {
                                retired_from_ms: second_retirement_ms,
                            },
                        ],
                        4,
                        &mut coverage,
                    );
                }
            }
        }
    }
    // Six orders of three steps at twenty schedules over four instants.
    let with_retirements = 6 * 20 * 4 * 3 * 6 * 6;
    assert_eq!(coverage.histories, with_retirements);

    // One change of the lifetimes and one retirement around one admission.
    for registered_lifetime_ms in [2, 3] {
        let initial = oracle.policy(registered_lifetime_ms);
        for issued_at_ms in FIRST_MS..FIRST_MS + 4 {
            for lifetime_ms in lifetimes.clone() {
                for changed_lifetime_ms in lifetimes.clone() {
                    for retired_from_ms in FIRST_MS..=FIRST_MS + 5 {
                        run_every_history(
                            &mut oracle,
                            &initial,
                            &[
                                HistoryStep::Admit {
                                    issued_at_ms,
                                    lifetime_ms,
                                },
                                HistoryStep::SetLifetimes {
                                    lifetime_ms: changed_lifetime_ms,
                                },
                                HistoryStep::Retire { retired_from_ms },
                            ],
                            4,
                            &mut coverage,
                        );
                    }
                }
            }
        }
    }
    let with_one_change = 2 * 6 * 20 * 4 * 3 * 3 * 6;
    assert_eq!(coverage.histories, with_retirements + with_one_change);

    // Two changes of the lifetimes, lowering twice or raising and lowering,
    // and one retirement around one admission.
    let initial = oracle.policy(3);
    for issued_at_ms in FIRST_MS..FIRST_MS + 3 {
        for lifetime_ms in lifetimes.clone() {
            for first_lifetime_ms in lifetimes.clone() {
                for second_lifetime_ms in lifetimes.clone() {
                    for retired_from_ms in FIRST_MS..=FIRST_MS + 3 {
                        run_every_history(
                            &mut oracle,
                            &initial,
                            &[
                                HistoryStep::Admit {
                                    issued_at_ms,
                                    lifetime_ms,
                                },
                                HistoryStep::SetLifetimes {
                                    lifetime_ms: first_lifetime_ms,
                                },
                                HistoryStep::SetLifetimes {
                                    lifetime_ms: second_lifetime_ms,
                                },
                                HistoryStep::Retire { retired_from_ms },
                            ],
                            3,
                            &mut coverage,
                        );
                    }
                }
            }
        }
    }
    // Twenty-four orders of four steps at fifteen schedules over three instants.
    let with_two_changes = 24 * 15 * 3 * 3 * 3 * 3 * 4;
    assert_eq!(
        coverage.histories,
        with_retirements + with_one_change + with_two_changes
    );

    // The enumeration admitted credentials, removed keys after them and met
    // the boundary where the removal instant is the expiry of a credential.
    assert!(coverage.admitted > 0);
    assert!(coverage.removals > 0);
    assert!(coverage.tight > 0);
}

#[test]
fn revoked_keys_keep_their_slots_for_ever() {
    let transition =
        |message: &'static str| PhoneControlError::InvalidProviderKeyTransition(message);
    let capacity = Err(PhoneControlError::ProviderKeyCapacity {
        limit: PHONE_CONTROL_V1_MAX_PROVIDER_KEYS,
    });
    let register = |policy: &mut PhoneControlProviderPolicyV1, seed: usize, now_ms: u64| {
        let pair = ed25519(u8::try_from(seed).unwrap());
        policy
            .register_key(pair.public_key().clone(), now_ms, now_ms)
            .map(|_| ())
    };

    // Every slot of the namespace holds a revoked key.
    let mut policy = provider_policy_with(&[]);
    for seed in 1..=PHONE_CONTROL_V1_MAX_PROVIDER_KEYS {
        register(&mut policy, seed, REGISTERED_AT_MS).unwrap();
        let id = key_id(&ed25519(u8::try_from(seed).unwrap()));
        policy.revoke_key(&id, REGISTERED_AT_MS).unwrap();
    }
    policy.validate().unwrap();
    assert_eq!(policy.keys.len(), PHONE_CONTROL_V1_MAX_PROVIDER_KEYS);
    // No key is registered at any later time and no slot is freed: the
    // namespace admits no further credential.
    for now_ms in [REGISTERED_AT_MS, ISSUED_AT_MS, u64::MAX] {
        assert_eq!(register(&mut policy, 0xEE, now_ms), capacity);
    }
    for key in policy.keys.clone() {
        let id = key.id().unwrap();
        assert_eq!(
            policy.remove_retired_key(&id, u64::MAX),
            Err(transition("only a retired key is removed"))
        );
        assert_eq!(
            policy.retire_key(&id, u64::MAX, REGISTERED_AT_MS),
            Err(transition("revocation is terminal"))
        );
    }
    let record = PhoneControlChallengeV1 {
        provider: key_id(&ed25519(1)),
        ..challenge()
    };
    assert_eq!(
        issue(&record, &ed25519(1), ISSUED_AT_MS).verify(&policy, &context(), ISSUED_AT_MS),
        Err(PhoneControlError::ProviderKeyRevoked)
    );

    // A retired key frees its slot when it is removed. A revoked one beside
    // it does not.
    let mut policy = provider_policy_with(&[]);
    for seed in 1..=PHONE_CONTROL_V1_MAX_PROVIDER_KEYS {
        register(&mut policy, seed, REGISTERED_AT_MS).unwrap();
    }
    let retired = key_id(&ed25519(1));
    let revoked = key_id(&ed25519(2));
    policy
        .retire_key(&retired, REGISTERED_AT_MS, REGISTERED_AT_MS)
        .unwrap();
    policy.revoke_key(&revoked, REGISTERED_AT_MS).unwrap();
    let removable_from_ms = REGISTERED_AT_MS + MAX_CREDENTIAL_MS;
    assert_eq!(register(&mut policy, 0xEE, removable_from_ms), capacity);
    policy
        .remove_retired_key(&retired, removable_from_ms)
        .unwrap();
    register(&mut policy, 0xEE, removable_from_ms).unwrap();
    assert_eq!(register(&mut policy, 0xEF, removable_from_ms), capacity);
    assert_eq!(
        policy.key(&revoked).unwrap().state,
        PhoneControlProviderKeyStateV1::Revoked {
            compromised_from_ms: REGISTERED_AT_MS
        }
    );
}

#[test]
fn provider_policy_rejects_malformed_records_and_is_bounded() {
    let invalid = |message: &'static str| Err(PhoneControlError::InvalidProviderPolicy(message));
    let new = |credential_ms: u64, binding_ms: u64| {
        PhoneControlProviderPolicyV1::new(namespace("phone#retail"), credential_ms, binding_ms)
            .map(|_| ())
    };
    assert_eq!(new(0, 1), invalid("credential lifetime must not be zero"));
    assert_eq!(new(1, 0), invalid("binding lifetime must not be zero"));
    assert_eq!(
        new(1, 2),
        invalid("binding lifetime exceeds the credential lifetime")
    );
    new(1, 1).unwrap();
    new(u64::MAX, u64::MAX).unwrap();

    let valid = provider_policy();
    // Keys out of order and a repeated key are not a canonical policy.
    let mut unordered = valid.clone();
    unordered.keys.reverse();
    assert_eq!(
        unordered.validate(),
        invalid("provider keys are not in strictly ascending order of identity")
    );
    let mut repeated = valid.clone();
    repeated.keys[1] = repeated.keys[0].clone();
    assert_eq!(
        repeated.validate(),
        invalid("provider keys are not in strictly ascending order of identity")
    );
    let mut inverted = valid.clone();
    inverted.keys[0].state = PhoneControlProviderKeyStateV1::Retired {
        retired_from_ms: REGISTERED_AT_MS - 1,
    };
    assert_eq!(
        inverted.validate(),
        invalid("provider key retires before it becomes active")
    );
    let mut unsupported = valid.clone();
    unsupported.keys[0].public_key = KeyPair::try_from_seed(vec![9; 32], Algorithm::Secp256k1)
        .unwrap()
        .public_key()
        .clone();
    assert_eq!(
        unsupported.validate(),
        Err(PhoneControlError::UnsupportedProviderKeyAlgorithm)
    );
    // Evidence is never admitted under a malformed policy.
    for malformed in [&unordered, &repeated, &inverted, &unsupported] {
        assert!(malformed.commitment().is_err());
        assert!(
            evidence()
                .verify(malformed, &context(), ISSUED_AT_MS)
                .is_err()
        );
    }

    // The policy holds at most the committed number of keys, in every state.
    let mut full = provider_policy_with(&[]);
    for seed in 0..PHONE_CONTROL_V1_MAX_PROVIDER_KEYS {
        let seed = u8::try_from(seed + 1).unwrap();
        full.register_key(ed25519(seed).public_key().clone(), REGISTERED_AT_MS, 0)
            .unwrap();
    }
    full.validate().unwrap();
    assert_eq!(full.keys.len(), PHONE_CONTROL_V1_MAX_PROVIDER_KEYS);
    assert_eq!(PHONE_CONTROL_V1_MAX_PROVIDER_KEYS, 32);
    let capacity = Err(PhoneControlError::ProviderKeyCapacity { limit: 32 });
    assert_eq!(
        full.register_key(ed25519(0xEE).public_key().clone(), REGISTERED_AT_MS, 0)
            .map(|_| ()),
        capacity
    );
    // Retiring and revoking keeps the slot.
    let retired = full.keys[0].id().unwrap();
    full.retire_key(&retired, REGISTERED_AT_MS, 0).unwrap();
    let revoked = full.keys[1].id().unwrap();
    full.revoke_key(&revoked, 0).unwrap();
    assert_eq!(
        full.register_key(ed25519(0xEE).public_key().clone(), REGISTERED_AT_MS, 0)
            .map(|_| ()),
        capacity
    );
    let mut oversized = full.clone();
    oversized.keys.push(PhoneControlProviderKeyV1 {
        public_key: ed25519(0xEE).public_key().clone(),
        active_from_ms: 0,
        state: PhoneControlProviderKeyStateV1::Active,
    });
    assert_eq!(oversized.validate(), capacity);
}

#[test]
fn provider_policy_commitment_is_the_documented_framing_and_binds_every_field() {
    let policy = provider_policy();
    let commitment = policy.commitment().unwrap();
    let frame = norito::encode_canonical(&policy).unwrap();
    assert_eq!(
        commitment.as_hash(),
        &Hash::new(
            [
                b"iroha.ram_lfe.v1.phone_control.provider_policy".as_slice(),
                &frame
            ]
            .concat()
        )
    );

    let mut variants = Vec::new();
    let mut other = policy.clone();
    other.identifier_policy = namespace("phone#wholesale");
    variants.push(("identifier_policy", other));
    let mut other = policy.clone();
    other.max_credential_lifetime_ms += 1;
    variants.push(("max_credential_lifetime_ms", other));
    let mut other = policy.clone();
    other.max_binding_lifetime_ms -= 1;
    variants.push(("max_binding_lifetime_ms", other));
    let mut other = policy.clone();
    other.longer_credentials_expire_by_ms += 1;
    variants.push(("longer_credentials_expire_by_ms", other));
    // The key set and every field of one key.
    let mut other = policy.clone();
    other.keys.pop();
    variants.push(("keys", other));
    let mut other = policy.clone();
    other.keys[0].active_from_ms += 1;
    variants.push(("keys", other));
    let mut other = policy.clone();
    other
        .retire_key(&key_id(&provider()), ISSUED_AT_MS, REGISTERED_AT_MS)
        .unwrap();
    variants.push(("keys", other.clone()));
    other
        .retire_key(&key_id(&provider()), ISSUED_AT_MS - 1, REGISTERED_AT_MS)
        .unwrap();
    variants.push(("keys", other.clone()));
    other
        .revoke_key(&key_id(&provider()), ISSUED_AT_MS)
        .unwrap();
    variants.push(("keys", other.clone()));
    other
        .revoke_key(&key_id(&provider()), ISSUED_AT_MS - 1)
        .unwrap();
    variants.push(("keys", other));
    variants.push(("keys", provider_policy_with(&[&provider(), &ed25519(0x66)])));

    let mut seen = vec![commitment];
    for (field, variant) in &variants {
        let commitment = variant.commitment().unwrap();
        assert!(
            !seen.contains(&commitment),
            "{field} must change the commitment"
        );
        seen.push(commitment);
    }
    let fields = schema_fields::<PhoneControlProviderPolicyV1>();
    for field in &fields {
        assert!(
            variants.iter().any(|(covered, _)| covered == field),
            "{field} is not substituted"
        );
    }
    assert_eq!(fields.len(), 5);
}

fn receipt(context: &PhoneControlContextV1, program_id: &RamLfeProgramId) -> RamLfeReceiptV1 {
    let replay = RamLfeReplayV1 {
        domain: RamLfeReplayDomainV1::IdentifierClaim,
        nonce: [0x5A; 32],
    };
    RamLfeReceiptV1 {
        policy: context.policy,
        network: context.network,
        program_id: program_id.clone(),
        beneficiary: context.beneficiary.clone(),
        associated_data: RamLfeAssociatedDataHashV1::commit(b"request").unwrap(),
        initialized_memory: RamLfeInitializedMemoryCommitmentV1::commit(
            &RamLfeProgramKeyV1::from_bytes([7; 32]).unwrap(),
            ram_policy(5).function.id().unwrap(),
            RamLfeAssociatedDataHashV1::commit(b"request").unwrap(),
            RamLfeExecutionContextIdV1::commit(b"execution").unwrap(),
            &RamLfeInitialMemoryV1::from_lanes(&[9; 32]).unwrap(),
        )
        .unwrap(),
        input_ciphertext: RamLfeInputCiphertextCommitmentV1::commit(b"input").unwrap(),
        output_ciphertext: RamLfeOutputCiphertextCommitmentV1::commit(b"output").unwrap(),
        expires_at_ms: EXPIRES_AT_MS,
        replay,
    }
}

#[test]
fn receipt_must_belong_to_the_same_claim_as_the_control_evidence() {
    let context = context();
    let program: RamLfeProgramId = "phone_retail".parse().unwrap();
    let matching = receipt(&context, &program);
    context.verify_receipt(&matching, &program).unwrap();
    let rejected = |receipt: &RamLfeReceiptV1, program: &RamLfeProgramId, field: &'static str| {
        assert_eq!(
            context.verify_receipt(receipt, program),
            Err(PhoneControlError::ContextMismatch(field))
        );
    };
    rejected(
        &RamLfeReceiptV1 {
            network: network(b"another genesis"),
            ..matching.clone()
        },
        &program,
        "receipt network",
    );
    rejected(
        &RamLfeReceiptV1 {
            policy: ram_policy(6).commitment().unwrap(),
            ..matching.clone()
        },
        &program,
        "receipt policy",
    );
    // The namespace resolves to one program; a receipt of another program
    // with the same policy is not a receipt of this claim.
    rejected(
        &matching,
        &"email_retail".parse().unwrap(),
        "receipt program",
    );
    rejected(
        &RamLfeReceiptV1 {
            beneficiary: account(2),
            ..matching.clone()
        },
        &program,
        "receipt beneficiary",
    );
    rejected(
        &RamLfeReceiptV1 {
            replay: RamLfeReplayV1 {
                domain: RamLfeReplayDomainV1::Execution,
                ..matching.replay
            },
            ..matching.clone()
        },
        &program,
        "receipt replay scope",
    );
    // The receipt expiry is one of the bounds of the binding.
    let admission = admit(&evidence()).unwrap();
    assert_eq!(
        admission.earliest_expiry_ms(&[matching.expires_at_ms - 7]),
        Ok(EXPIRES_AT_MS - 7)
    );
}

#[test]
fn every_normalized_spelling_of_one_number_gives_one_witness() {
    let spellings = [
        "+15551234567",
        "+1 555 123 4567",
        "+1 (555) 123-4567",
        "001-555-123-4567",
        "1.555.123.4567",
        "  +15551234567  ",
    ];
    let commitments: Vec<PhoneNumberCommitmentV1> = spellings
        .iter()
        .map(|spelling| {
            let canonical = IdentifierNormalization::PhoneE164
                .normalize(spelling)
                .unwrap();
            assert_eq!(canonical, "+15551234567");
            commitment(canonical.as_bytes(), 0x42)
        })
        .collect();
    assert!(commitments.iter().all(|other| *other == commitments[0]));
    // The witness takes the canonical value only: a spelling the normalization
    // would still have to rewrite is refused.
    for spelling in &spellings[1..] {
        assert_eq!(
            PhoneNumberV1::from_canonical(spelling.as_bytes()).unwrap_err(),
            PhoneControlError::NonCanonicalNumber
        );
    }
    // Everything the normalization produces is a canonical witness.
    for raw in [
        "+12",
        "+123456789012345",
        "0044 20 7946 0958",
        "81-3-1234-5678",
    ] {
        let canonical = IdentifierNormalization::PhoneE164.normalize(raw).unwrap();
        PhoneNumberV1::from_canonical(canonical.as_bytes()).unwrap();
    }
}

#[test]
fn phone_control_domains_are_distinct_and_prefix_free_with_every_v1_table() {
    let all: Vec<&[u8]> = RAM_LFE_V1_PUBLIC_DOMAINS
        .iter()
        .chain(&RAM_LFE_V1_MODEL_DOMAINS)
        .chain(&PHONE_CONTROL_V1_CRYPTO_DOMAINS)
        .chain(&PHONE_CONTROL_V1_MODEL_DOMAINS)
        .copied()
        .collect();
    assert_eq!(all.len(), 13 + 2 + 1 + 3);
    for (index, domain) in all.iter().enumerate() {
        assert!(domain.starts_with(b"iroha.ram_lfe.v1."));
        for (other_index, other) in all.iter().enumerate() {
            assert!(
                index == other_index || !other.starts_with(domain),
                "a domain must not be a prefix of another"
            );
        }
    }
    for domain in PHONE_CONTROL_V1_MODEL_DOMAINS {
        assert!(domain.starts_with(b"iroha.ram_lfe.v1.phone_control."));
    }
}

fn schema_fields<T: IntoSchema>() -> Vec<String> {
    match T::schema().get::<T>() {
        Some(iroha_schema::Metadata::Struct(meta)) => meta
            .declarations
            .iter()
            .map(|declaration| declaration.name.clone())
            .collect(),
        other => panic!("{} is not a named-field record: {other:?}", T::type_name()),
    }
}

fn specification() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/ram_lfe_execution_proof.md"
    );
    std::fs::read_to_string(path).expect("tracked RAM-LFE specification")
}

/// The provider-control section of the specification, to the next section.
fn section(document: &str) -> &str {
    let start = document
        .find("\n## Provider-backed phone control\n")
        .expect("specification has the provider-control section");
    let body = &document[start + 1..];
    let end = body[3..].find("\n## ").map_or(body.len(), |end| end + 3);
    &body[..end]
}

/// The row of the section that defines one record, and the field names it
/// lists after the record name, in order.
fn specified_record<'a>(section: &'a str, record: &str) -> (&'a str, Vec<&'a str>) {
    let marker = format!("`{record}`: ");
    let mut rows = section.lines().filter(|line| line.contains(&marker));
    let row = rows
        .next()
        .unwrap_or_else(|| panic!("specification has no field row for {record}"));
    assert!(
        rows.next().is_none(),
        "specification defines {record} more than once"
    );
    let fields = row[row.find(&marker).unwrap() + marker.len()..]
        .split('|')
        .next()
        .unwrap();
    (row, fields.split('`').skip(1).step_by(2).collect())
}

#[test]
fn specification_field_order_is_the_model_record_definitions() {
    let document = specification();
    let section = section(&document);
    let records: [(&str, &str, Vec<String>); 6] = [
        (
            "iroha.ram_lfe.v1.phone_control.provider_policy",
            "PhoneControlProviderPolicyV1",
            schema_fields::<PhoneControlProviderPolicyV1>(),
        ),
        (
            "",
            "PhoneControlProviderKeyV1",
            schema_fields::<PhoneControlProviderKeyV1>(),
        ),
        (
            "iroha.ram_lfe.v1.phone_control.challenge",
            "PhoneControlChallengeV1",
            schema_fields::<PhoneControlChallengeV1>(),
        ),
        (
            "iroha.ram_lfe.v1.phone_control.credential",
            "PhoneControlCredentialV1",
            schema_fields::<PhoneControlCredentialV1>(),
        ),
        (
            "",
            "PhoneControlSignedCredentialV1",
            schema_fields::<PhoneControlSignedCredentialV1>(),
        ),
        (
            "",
            "PhoneControlEvidenceV1",
            schema_fields::<PhoneControlEvidenceV1>(),
        ),
    ];
    for (domain, record, fields) in &records {
        let (row, specified) = specified_record(section, record);
        assert_eq!(&specified, fields, "field order of {record}");
        assert!(!fields.is_empty());
        assert!(
            domain.is_empty() || row.contains(&format!("`{domain}`")),
            "the row of {record} must name {domain}"
        );
    }
    for domain in PHONE_CONTROL_V1_MODEL_DOMAINS {
        let domain = std::str::from_utf8(domain).unwrap();
        assert!(
            records.iter().any(|(named, ..)| named == &domain),
            "domain {domain} has no record row"
        );
    }

    // No other record is specified in the section: every `Phone…V1`: marker is
    // one of the records above or one of the two frames the crypto crate's own
    // test compares with their definitions.
    let crypto = ["PhoneNumberCommitmentV1", "PhoneControlProviderKeyInputV1"];
    let mut markers = 0;
    for piece in section.split("`: ") {
        let name = piece.rsplit('`').next().unwrap();
        if name.starts_with("Phone") && name.ends_with("V1") {
            markers += 1;
            assert!(
                records.iter().any(|(_, record, _)| record == &name) || crypto.contains(&name),
                "specification defines an unknown record {name}"
            );
        }
    }
    assert_eq!(markers, records.len() + crypto.len());
}

/// The key lifecycle table of the specification: state, issuance rule, eviction rule.
fn lifecycle_rows(section: &str) -> Vec<Vec<&str>> {
    let marker = "<!-- phone-control-provider-key-lifecycle -->";
    let start = section
        .find(marker)
        .expect("specification carries the provider key lifecycle table")
        + marker.len();
    section[start..]
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| line.trim_matches('|').split('|').map(str::trim).collect())
        .collect()
}

#[test]
fn specification_states_the_lifecycle_and_the_bounds_the_code_enforces() {
    let document = specification();
    let section = section(&document);
    // One row for each state of the lifecycle, in declaration order.
    let rows = lifecycle_rows(section);
    let states: Vec<&str> = rows
        .iter()
        .map(|row| {
            assert_eq!(row.len(), 3, "lifecycle row has three cells: {row:?}");
            row[0].split('`').nth(1).unwrap()
        })
        .collect();
    assert_eq!(states, ["Active", "Retired", "Revoked"]);
    assert!(rows[0][1].contains("`active_from_ms <= issued_at_ms`"));
    assert!(rows[1][1].contains("`active_from_ms <= issued_at_ms < retired_from_ms`"));
    assert!(rows[2][1].starts_with("Nothing"));
    assert!(rows[2][2].contains("`>= compromised_from_ms`"));

    // The admission interval, the lifetime bound and the key bound, as tested.
    assert!(section.contains("`issued_at_ms <= now_ms < expires_at_ms`"));
    assert!(section.contains("`expires_at_ms - issued_at_ms <= max_credential_lifetime_ms`"));
    assert!(section.contains("`issued_at_ms + max_binding_lifetime_ms`"));
    assert!(section.contains("`max_binding_lifetime_ms <= max_credential_lifetime_ms`"));
    assert!(section.contains("strictly after the admission time"));
    assert!(section.contains("first valid claim admitted in ledger order"));
    assert!(section.contains(&format!(
        "at most {PHONE_CONTROL_V1_MAX_PROVIDER_KEYS} keys"
    )));
    assert!(section.contains("Ed25519 or ML-DSA-65"));
    // The rules that keep a key record while anything depends on it.
    assert!(section.contains("A retirement is never backdated"));
    assert!(section.contains(
        "`now_ms >= max(retired_from_ms + max_credential_lifetime_ms, \
         longer_credentials_expire_by_ms)`"
    ));
    assert!(section.contains("`set_lifetimes` is the only change"));
    assert!(section.contains(&format!(
        "After {PHONE_CONTROL_V1_MAX_PROVIDER_KEYS} revocations every slot holds a revoked key"
    )));
    assert!(section.contains("recorded value is the expiry of the credential"));
    // The honest limits are stated, and no approval gate is.
    for required in [
        "The provider learns the number",
        "### Issuer compromise",
        "### SIM takeover",
        "### Number recycling and reassignment",
        "Canonical format and uniqueness do not show control",
    ] {
        assert!(
            section.contains(required),
            "specification lacks: {required}"
        );
    }
}

#[test]
fn control_evidence_carries_no_canonicality_attestor_and_no_approval() {
    // The evidence of a claim is the challenge record and the signed
    // credential, and the provider policy holds provider keys, two lifetimes
    // and one expiry record of an earlier lifetime. No record has a field for
    // a canonicality attestation, a reviewer or an approval.
    let fields: Vec<String> = [
        schema_fields::<PhoneControlEvidenceV1>(),
        schema_fields::<PhoneControlSignedCredentialV1>(),
        schema_fields::<PhoneControlCredentialV1>(),
        schema_fields::<PhoneControlChallengeV1>(),
        schema_fields::<PhoneControlProviderPolicyV1>(),
        schema_fields::<PhoneControlProviderKeyV1>(),
    ]
    .concat();
    assert_eq!(fields.len(), 2 + 2 + 9 + 9 + 5 + 3);
    for field in &fields {
        for gate in [
            "canonical",
            "attest",
            "approv",
            "review",
            "audit",
            "activat",
        ] {
            assert!(!field.contains(gate), "{field} names a gate");
        }
    }
    // Neither owner names the canonicality attestor types, which task R.4
    // removes; the contract does not depend on them.
    for path in [
        "/src/phone_control.rs",
        "/../iroha_crypto/src/ram_lfe/phone_control.rs",
    ] {
        let source = std::fs::read_to_string(format!("{}{path}", env!("CARGO_MANIFEST_DIR")))
            .expect("phone-control owner source");
        for retired in ["PhoneRetailCanonicality", "phone_retail_attestor"] {
            assert!(!source.contains(retired), "{path} names {retired}");
        }
    }
}

#[test]
fn phone_control_model_vectors_are_pinned() {
    let evidence = evidence();
    let vectors = [
        hex::encode(key_id(&provider()).as_hash().as_ref()),
        hex::encode(evidence.challenge.id().unwrap().as_hash().as_ref()),
        hex::encode(
            provider_policy_with(&[&provider()])
                .commitment()
                .unwrap()
                .as_hash()
                .as_ref(),
        ),
        // Ed25519 signing is deterministic, so the credential signature is a vector too.
        hex::encode(evidence.credential.signature.payload()),
    ];
    assert_eq!(
        vectors,
        [
            "3338b95d19c1b1100933eb069ecb12050367b89d052a9160241c43afbc2c2f6d",
            "174293f35117021322b6c26462c35eb9661d7d12d5207313545412d344be8869",
            "aca66e5781ee62ba262aa73036dfde0dc14203fb87ed83f0146b71a73d227d41",
            "5f412b9065dbc4679491aadd4057a21aa954c3d337f629c5200c8b60c350f4453a7480296bbc625b111361a08711978e318ed5ff7f3619961cc0393d4cd0b10c",
        ]
    );
}
