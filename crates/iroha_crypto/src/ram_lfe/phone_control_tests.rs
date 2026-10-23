//! Provider-backed phone control: number commitment, provider key identity and signature rule.

use super::*;
use crate::{
    KeyPair,
    ram_lfe::{
        RAM_LFE_V1_PRIVATE_CONTEXTS, RAM_LFE_V1_PUBLIC_DOMAINS, RamLfeError,
        RamLfeReferenceInputV1, clearing::cleared_cells, derive_phone_retail_nullifier_v1,
    },
};

const NUMBER: &[u8] = b"+15551234567";
const SHORTEST: &[u8] = b"+12";
const LONGEST: &[u8] = b"+123456789012345";

fn number(bytes: &[u8]) -> PhoneNumberV1 {
    PhoneNumberV1::from_canonical(bytes).unwrap()
}

fn blinding(byte: u8) -> PhoneNumberBlindingV1 {
    PhoneNumberBlindingV1::from_bytes([byte; 32]).unwrap()
}

const DIGEST: PhoneNumberCommitmentDigestV1 = PhoneNumberCommitmentDigestV1::GoldilocksDigest384V1;

/// The Goldilocks modulus, read from the canonical field descriptor of the
/// proof backend so that no second definition of it exists here.
fn field_modulus() -> u64 {
    fastpq_isi::GOLDILOCKS_FP4_V1
        .modulus_decimal
        .parse()
        .expect("the canonical field descriptor states the modulus")
}

fn commitment(bytes: &[u8], blinding_byte: u8) -> PhoneNumberCommitmentV1 {
    PhoneNumberCommitmentV1::commit(DIGEST, &number(bytes), &blinding(blinding_byte))
}

fn ed25519(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}

#[cfg(feature = "pqc")]
fn mldsa(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::MlDsa).unwrap()
}

fn roundtrip<T>(value: &T)
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq + fmt::Debug,
{
    let frame = norito::encode_canonical(value).unwrap();
    assert_eq!(&norito::decode_canonical::<T>(&frame).unwrap(), value);
    assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
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

#[test]
fn canonical_e164_is_exactly_what_the_nullifier_derivation_accepts() {
    // The nullifier and the commitment must admit the same set of numbers:
    // one number never has a commitment without a nullifier or the reverse.
    let candidates = [
        "+15551234567",
        "+12",
        "+123456789012345",
        "+1234567890123456",
        "+1",
        "+",
        "",
        "15551234567",
        "0015551234567",
        "+05551234567",
        "+1555 1234567",
        "+1-555-1234567",
        "+1(555)1234567",
        " +15551234567",
        "+15551234567 ",
        "+1555123456a",
        "+١٢٣٤٥",
        "+1\u{0}5",
        "++15551234567",
        "+15551234567\n",
    ];
    let mut accepted = 0;
    for candidate in candidates {
        let commitment_admits = PhoneNumberV1::from_canonical(candidate.as_bytes()).is_ok();
        let nullifier_admits = !matches!(
            derive_phone_retail_nullifier_v1(&[7; 32], &[1; 32], candidate),
            Err(RamLfeError::NonCanonicalPhone)
        );
        assert_eq!(commitment_admits, nullifier_admits, "{candidate:?}");
        accepted += usize::from(commitment_admits);
    }
    assert_eq!(accepted, 3);
    // Bytes that are not text are not a number either.
    assert_eq!(
        PhoneNumberV1::from_canonical(&[b'+', b'1', 0xFF]).unwrap_err(),
        PhoneControlError::NonCanonicalNumber
    );
    // Every first digit and every length inside the bounds is admitted.
    for first in b'1'..=b'9' {
        for digits in 2..=15 {
            let mut bytes = vec![b'+', first];
            bytes.resize(1 + digits, b'0');
            assert!(PhoneNumberV1::from_canonical(&bytes).is_ok());
        }
    }
}

#[test]
fn number_field_is_input_slots_one_to_sixteen_of_the_canonical_input() {
    for canonical in [SHORTEST, NUMBER, LONGEST] {
        let owner = number(canonical);
        assert_eq!(owner.expose_canonical(), canonical);
        let padded = owner.expose_padded();
        assert_eq!(&padded[..canonical.len()], canonical);
        assert!(padded[canonical.len()..].iter().all(|byte| *byte == 0));

        // The admitted RAM-LFE input of the same bytes: slot 0 is the length,
        // slots 1..=16 are the committed field and every later slot is zero.
        let input = RamLfeReferenceInputV1::from_bytes(canonical).unwrap();
        let slots = input.slots();
        assert_eq!(usize::from(slots[0]), canonical.len());
        for (slot, byte) in slots[1..=PHONE_CONTROL_V1_NUMBER_BYTES].iter().zip(padded) {
            assert_eq!(*slot, u16::from(*byte));
        }
        assert!(
            slots[PHONE_CONTROL_V1_NUMBER_BYTES + 1..]
                .iter()
                .all(|slot| *slot == 0)
        );
    }
    assert_eq!(LONGEST.len(), PhoneNumberV1::MAX_BYTES);
    assert_eq!(SHORTEST.len(), PhoneNumberV1::MIN_BYTES);
    assert_eq!(format!("{:?}", number(NUMBER)), "[REDACTED phone number]");
}

#[test]
fn padding_is_injective() {
    // A number and its extension by one digit share a prefix and nothing else.
    let short = number(b"+1555");
    let long = number(b"+15550");
    assert_ne!(short.expose_padded(), long.expose_padded());
    assert_ne!(commitment(b"+1555", 3), commitment(b"+15550", 3));
    // No canonical number contains the padding byte.
    for canonical in [SHORTEST, NUMBER, LONGEST] {
        assert!(!canonical.contains(&0));
    }
}

#[test]
fn blinding_is_validated_and_redacted() {
    assert_eq!(
        PhoneNumberBlindingV1::from_bytes([0; 32]).unwrap_err(),
        PhoneControlError::ZeroBlinding
    );
    assert_eq!(blinding(9).expose(), &[9; 32]);
    assert_eq!(
        format!("{:?}", blinding(9)),
        "[REDACTED phone-number blinding]"
    );
    assert_eq!(PhoneNumberBlindingV1::LENGTH, 32);
}

#[cfg(feature = "rand")]
#[test]
fn blinding_is_generated_fresh() {
    let first = PhoneNumberBlindingV1::generate().unwrap();
    let second = PhoneNumberBlindingV1::generate().unwrap();
    assert_ne!(first.expose(), second.expose());
    assert_ne!(first.expose(), &[0; 32]);
}

#[test]
fn witnesses_keep_one_address_and_clear_on_success_error_and_unwind() {
    // A move of the owner moves a pointer: the secret bytes stay where they are.
    let owner = number(NUMBER);
    let address = owner.expose_padded().as_ptr();
    let moved = Box::new(std::convert::identity(owner));
    assert_eq!(moved.expose_padded().as_ptr(), address);
    let secret = blinding(0x5A);
    let address = secret.expose().as_ptr();
    let moved_secret = Some(secret);
    assert_eq!(moved_secret.as_ref().unwrap().expose().as_ptr(), address);

    // Success: the number clears its 16 bytes and the blinding its 32.
    let before = cleared_cells();
    drop(moved);
    drop(moved_secret);
    assert_eq!(cleared_cells() - before, 16 + 32);

    // Success through the commitment that borrows them.
    let before = cleared_cells();
    {
        let number = number(NUMBER);
        let blinding = blinding(7);
        let commitment = PhoneNumberCommitmentV1::commit(DIGEST, &number, &blinding);
        commitment.verify_opening(&number, &blinding).unwrap();
    }
    assert_eq!(cleared_cells() - before, 16 + 32);

    // Error: a rejected blinding clears the copy it made, and a rejected
    // number is refused before any copy exists.
    let before = cleared_cells();
    assert!(PhoneNumberBlindingV1::from_bytes([0; 32]).is_err());
    assert_eq!(cleared_cells() - before, 32);
    let before = cleared_cells();
    assert!(PhoneNumberV1::from_canonical(b"15551234567").is_err());
    assert_eq!(cleared_cells() - before, 0);

    // Error: a failed opening check clears both witnesses when they drop.
    let before = cleared_cells();
    {
        let number = number(NUMBER);
        let blinding = blinding(7);
        assert_eq!(
            commitment(NUMBER, 8).verify_opening(&number, &blinding),
            Err(PhoneControlError::CommitmentMismatch)
        );
    }
    // The two local witnesses, and the two the helper built for the commitment.
    assert_eq!(cleared_cells() - before, 2 * (16 + 32));

    // Unwind: a panic while the witnesses are live clears them.
    let before = cleared_cells();
    assert!(
        std::panic::catch_unwind(|| {
            let _number = number(NUMBER);
            let _blinding = blinding(3);
            panic!("witness unwind control");
        })
        .is_err()
    );
    assert_eq!(cleared_cells() - before, 16 + 32);
}

/// The commitment recomputed from literals through the digest owner.
fn framed(
    domain: GoldilocksDigestDomainV1<'_>,
    number: &[u8; 16],
    blinding: &[u8; 32],
) -> [u8; 48] {
    hash_bytes_384_v1(domain, &[number, blinding])
        .unwrap()
        .to_le_bytes()
}

const DOCUMENTED_DOMAIN: GoldilocksDigestDomainV1<'static> = GoldilocksDigestDomainV1 {
    catalog: b"iroha-privacy-exact12-v1",
    protocol: b"iroha.ram_lfe.v1.phone_control",
    profile: b"goldilocks-digest384-v1",
    role: b"number-commitment",
    phase: b"",
    level: 0,
    index: 0,
    counter: 0,
};

fn padded(canonical: &[u8]) -> [u8; 16] {
    let mut field = [0_u8; 16];
    field[..canonical.len()].copy_from_slice(canonical);
    field
}

#[test]
fn number_commitment_is_the_documented_framing() {
    assert_eq!(FASTPQ_CATALOG_V1.as_bytes(), DOCUMENTED_DOMAIN.catalog);
    assert_eq!(
        PHONE_CONTROL_V1_NUMBER_COMMITMENT_PROTOCOL.as_bytes(),
        DOCUMENTED_DOMAIN.protocol
    );
    assert_eq!(DIGEST.label().as_bytes(), DOCUMENTED_DOMAIN.profile);
    assert_eq!(
        PHONE_CONTROL_V1_NUMBER_COMMITMENT_ROLE.as_bytes(),
        DOCUMENTED_DOMAIN.role
    );
    assert_eq!(PHONE_CONTROL_V1_NUMBER_BYTES, 16);
    assert_eq!(PHONE_CONTROL_V1_BLINDING_BYTES, 32);

    for canonical in [SHORTEST, NUMBER, LONGEST] {
        let committed = commitment(canonical, 0x42);
        let expected = framed(DOCUMENTED_DOMAIN, &padded(canonical), &[0x42; 32]);
        assert_eq!(committed.to_le_bytes(), expected);
        assert_eq!(committed.digest(), DIGEST);
        // The six words are the lanes of the digest, in order, little endian.
        let words = committed.lane_words();
        for (lane, word) in words.iter().enumerate() {
            assert!(*word < field_modulus());
            assert_eq!(word.to_le_bytes(), expected[lane * 8..lane * 8 + 8]);
        }
        assert_eq!(
            PhoneNumberCommitmentV1::from_le_bytes(DIGEST, expected).unwrap(),
            committed
        );
    }
}

#[test]
fn number_commitment_binds_the_number_the_blinding_and_every_domain_field() {
    let committed = commitment(NUMBER, 0x42);
    committed
        .verify_opening(&number(NUMBER), &blinding(0x42))
        .unwrap();

    // Every digit of the number and its length.
    for position in 1..NUMBER.len() {
        let mut other = NUMBER.to_vec();
        other[position] = if other[position] == b'9' { b'8' } else { b'9' };
        assert_ne!(commitment(&other, 0x42), committed);
        assert_eq!(
            committed.verify_opening(&number(&other), &blinding(0x42)),
            Err(PhoneControlError::CommitmentMismatch)
        );
    }
    for other in [&NUMBER[..NUMBER.len() - 1], b"+155512345670".as_slice()] {
        assert_eq!(
            committed.verify_opening(&number(other), &blinding(0x42)),
            Err(PhoneControlError::CommitmentMismatch)
        );
    }

    // Every byte of the blinding.
    for position in 0..32 {
        let mut other = [0x42_u8; 32];
        other[position] ^= 1;
        let other = PhoneNumberBlindingV1::from_bytes(other).unwrap();
        assert_eq!(
            committed.verify_opening(&number(NUMBER), &other),
            Err(PhoneControlError::CommitmentMismatch)
        );
    }

    // Every field of the typed domain, and the order of the two byte fields.
    let field = padded(NUMBER);
    let expected = committed.to_le_bytes();
    assert_eq!(framed(DOCUMENTED_DOMAIN, &field, &[0x42; 32]), expected);
    let mutated: [GoldilocksDigestDomainV1<'static>; 8] = [
        GoldilocksDigestDomainV1 {
            catalog: b"iroha-privacy-exact12-v2",
            ..DOCUMENTED_DOMAIN
        },
        GoldilocksDigestDomainV1 {
            protocol: b"iroha.ram_lfe.v1.phone_contro1",
            ..DOCUMENTED_DOMAIN
        },
        GoldilocksDigestDomainV1 {
            profile: b"goldilocks-digest384-v2",
            ..DOCUMENTED_DOMAIN
        },
        GoldilocksDigestDomainV1 {
            role: b"number-commitmenT",
            ..DOCUMENTED_DOMAIN
        },
        GoldilocksDigestDomainV1 {
            phase: b"0",
            ..DOCUMENTED_DOMAIN
        },
        GoldilocksDigestDomainV1 {
            level: 1,
            ..DOCUMENTED_DOMAIN
        },
        GoldilocksDigestDomainV1 {
            index: 1,
            ..DOCUMENTED_DOMAIN
        },
        GoldilocksDigestDomainV1 {
            counter: 1,
            ..DOCUMENTED_DOMAIN
        },
    ];
    for domain in mutated {
        assert_ne!(framed(domain, &field, &[0x42; 32]), expected);
    }
    // One field that holds both byte strings is another frame.
    let joined: Vec<u8> = field.iter().chain(&[0x42_u8; 32]).copied().collect();
    assert_ne!(
        hash_bytes_384_v1(DOCUMENTED_DOMAIN, &[&joined])
            .unwrap()
            .to_le_bytes(),
        expected
    );
}

#[test]
fn fresh_blinding_makes_commitments_to_one_number_unlinkable() {
    let first = commitment(NUMBER, 1);
    let second = commitment(NUMBER, 2);
    assert_ne!(first, second);
    // Not one lane of the two commitments coincides.
    for (left, right) in first.lane_words().iter().zip(second.lane_words()) {
        assert_ne!(*left, right);
    }
    // The same number and blinding give the same commitment: the provider
    // recomputes exactly what the client computed.
    assert_eq!(first, commitment(NUMBER, 1));
    // The nullifier input is the number alone. It does not change with the
    // blinding, so two commitments to one number share one nullifier.
    let nullifier = |canonical: &PhoneNumberV1| {
        derive_phone_retail_nullifier_v1(
            &[7; 32],
            &[1; 32],
            std::str::from_utf8(canonical.expose_canonical()).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(nullifier(&number(NUMBER)), nullifier(&number(NUMBER)));
    assert_ne!(nullifier(&number(NUMBER)), nullifier(&number(LONGEST)));
}

/// Hex of the pinned example commitment of the specification.
const PINNED_COMMITMENT: &str = "087ebe46155a3b3b006b68ed8dbe85eba1758ea13d0765454ca2c591d86ecf8b0f34b3a95ef9eee079e95cf27e3d1c43";

#[test]
fn number_commitment_vector_is_pinned_and_the_specification_carries_it() {
    let committed = commitment(NUMBER, 0x42);
    assert_eq!(hex::encode(committed.to_le_bytes()), PINNED_COMMITMENT);
    let document = specification();
    let section = section(&document);
    assert!(
        section.contains(&format!("`{PINNED_COMMITMENT}`")),
        "the specification must carry the pinned example commitment"
    );
    assert!(section.contains("`+15551234567`"));
}

#[test]
fn commitment_words_decode_strictly() {
    let committed = commitment(NUMBER, 0x42);
    roundtrip(&committed);
    roundtrip(&DIGEST);

    let canonical = committed.to_le_bytes();
    // A word at the modulus, above it and at the maximum is never reduced.
    for lane in 0..6 {
        for word in [field_modulus(), field_modulus() + 1, u64::MAX] {
            let mut bytes = canonical;
            bytes[lane * 8..lane * 8 + 8].copy_from_slice(&word.to_le_bytes());
            assert_eq!(
                PhoneNumberCommitmentV1::from_le_bytes(DIGEST, bytes).unwrap_err(),
                PhoneControlError::NonCanonicalCommitment
            );
            assert_eq!(
                PhoneNumberCommitmentValueV1::from_le_bytes(bytes).unwrap_err(),
                PhoneControlError::NonCanonicalCommitment
            );
        }
        // The largest canonical word is admitted.
        let mut bytes = canonical;
        bytes[lane * 8..lane * 8 + 8].copy_from_slice(&(field_modulus() - 1).to_le_bytes());
        let edge = PhoneNumberCommitmentV1::from_le_bytes(DIGEST, bytes).unwrap();
        assert_eq!(edge.lane_words()[lane], field_modulus() - 1);
        roundtrip(&edge);
    }

    // The decoder rejects the same words inside a canonical frame.
    let canonical_frame = norito::encode_canonical(&committed).unwrap();
    let flags = norito::core::from_bytes_view(&canonical_frame)
        .unwrap()
        .flags();
    let payload = committed.encode();
    let offset = payload
        .windows(48)
        .position(|window| window == canonical)
        .expect("the payload holds the 48 commitment bytes verbatim");
    for lane in 0..6 {
        for word in [field_modulus(), field_modulus() + 1, u64::MAX] {
            let mut forged = payload.clone();
            forged[offset + lane * 8..offset + lane * 8 + 8].copy_from_slice(&word.to_le_bytes());
            // Rebuild the header/checksum so the field decoder must reject it.
            let frame = norito::core::frame_bare_with_header_flags::<PhoneNumberCommitmentV1>(
                &forged, flags,
            )
            .unwrap();
            assert!(norito::decode_canonical::<PhoneNumberCommitmentV1>(&frame).is_err());

            let frame = norito::core::frame_bare_with_header_flags::<PhoneNumberCommitmentValueV1>(
                &forged[offset..offset + 48],
                flags,
            )
            .unwrap();
            assert!(matches!(
                norito::decode_canonical::<PhoneNumberCommitmentValueV1>(&frame),
                Err(norito::core::Error::InvalidValue {
                    context: "phone-number commitment word"
                })
            ));
        }
    }
    let value = PhoneNumberCommitmentValueV1::from_le_bytes(canonical).unwrap();
    roundtrip(&value);
    assert_eq!(value.to_le_bytes(), canonical);
    assert_eq!(value.words(), committed.lane_words());
    assert_eq!(PhoneNumberCommitmentValueV1::BYTES, 48);
    let mut forged = norito::encode_canonical(&value).unwrap();
    let offset = forged.len() - 48;
    forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(norito::decode_canonical::<PhoneNumberCommitmentValueV1>(&forged).is_err());
}

#[test]
fn commitment_value_payload_is_raw_and_bounded() {
    let bytes = commitment(NUMBER, 0x42).to_le_bytes();
    let value = PhoneNumberCommitmentValueV1::from_le_bytes(bytes).unwrap();
    assert_eq!(value.encode(), bytes);
    roundtrip(&value);
    roundtrip(&vec![value, value]);
    let canonical = norito::encode_canonical(&value).unwrap();
    let flags = norito::core::from_bytes_view(&canonical).unwrap().flags();
    let frame = |payload: &[u8]| {
        norito::core::frame_bare_with_header_flags::<PhoneNumberCommitmentValueV1>(payload, flags)
            .unwrap()
    };
    assert_eq!(frame(&bytes), canonical);
    for length in [0, 1, PhoneNumberCommitmentValueV1::BYTES - 1] {
        assert!(
            norito::decode_canonical::<PhoneNumberCommitmentValueV1>(&frame(&bytes[..length]))
                .is_err(),
            "short payload of {length} bytes"
        );
        assert!(
            <PhoneNumberCommitmentValueV1 as norito::core::DecodeFromSlice>::decode_from_slice(
                &bytes[..length]
            )
            .is_err()
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(norito::decode_canonical::<PhoneNumberCommitmentValueV1>(&frame(&trailing)).is_err());
    // The compositional slice decoder reports its prefix; a complete archive
    // must consume all of its bounded payload.
    assert_eq!(
        <PhoneNumberCommitmentValueV1 as norito::core::DecodeFromSlice>::decode_from_slice(
            &trailing
        )
        .unwrap(),
        (value, PhoneNumberCommitmentValueV1::BYTES)
    );
    let array_payload = bytes.encode();
    assert_ne!(array_payload, bytes);
    assert!(
        norito::decode_canonical::<PhoneNumberCommitmentValueV1>(&frame(&array_payload)).is_err(),
        "the generic array encoding is not a second commitment layout"
    );
}

#[test]
fn digest_identity_is_one_label_and_rejects_every_unknown_discriminant() {
    assert_eq!(DIGEST.label(), "goldilocks-digest384-v1");
    let canonical = norito::encode_canonical(&DIGEST).unwrap();
    let flags = norito::core::from_bytes_view(&canonical).unwrap().flags();
    let frame = |discriminant: u32| {
        norito::core::frame_bare_with_header_flags::<PhoneNumberCommitmentDigestV1>(
            &discriminant.to_le_bytes(),
            flags,
        )
        .unwrap()
    };
    assert_eq!(frame(0), canonical);
    // Exactly one identity is accepted. No second digest decodes.
    for discriminant in [1_u32, 2, 255, 256, u32::MAX] {
        assert!(
            norito::decode_canonical::<PhoneNumberCommitmentDigestV1>(&frame(discriminant))
                .is_err(),
            "discriminant {discriminant} must not decode"
        );
    }
}

// An independent owned shape with the declared frame identity reproduces the
// provider key identity from first principles.
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::PhoneControlProviderKeyInputV1",
    frame = "iroha_crypto::ram_lfe::PhoneControlProviderKeyInputV1"
)]
struct OwnedProviderKeyInput {
    algorithm: Algorithm,
    public_key: Vec<u8>,
}

fn owned_key_identity(algorithm: Algorithm, public_key: &[u8]) -> Hash {
    let frame = norito::encode_canonical(&OwnedProviderKeyInput {
        algorithm,
        public_key: public_key.to_vec(),
    })
    .unwrap();
    Hash::new(
        [
            b"iroha.ram_lfe.v1.phone_control.provider_key".as_slice(),
            &frame,
        ]
        .concat(),
    )
}

#[test]
fn provider_key_identity_is_the_documented_framing_and_tags_the_algorithm() {
    for pair in [
        ed25519(1),
        #[cfg(feature = "pqc")]
        mldsa(1),
    ] {
        let (algorithm, bytes) = pair.public_key().try_to_bytes().unwrap();
        let id = PhoneControlProviderKeyIdV1::commit(pair.public_key()).unwrap();
        assert_eq!(id.as_hash(), &owned_key_identity(algorithm, bytes));
        // The same bytes under the other algorithm tag are another identity.
        let other = if algorithm == Algorithm::Ed25519 {
            Algorithm::MlDsa
        } else {
            Algorithm::Ed25519
        };
        assert_ne!(id.as_hash(), &owned_key_identity(other, bytes));
        roundtrip(&id);
    }
    assert_ne!(
        PhoneControlProviderKeyIdV1::commit(ed25519(1).public_key()).unwrap(),
        PhoneControlProviderKeyIdV1::commit(ed25519(2).public_key()).unwrap()
    );
    assert_eq!(
        PhoneControlProviderKeyIdV1::commit(ed25519(1).public_key()).unwrap(),
        PhoneControlProviderKeyIdV1::commit(ed25519(1).public_key()).unwrap()
    );
}

/// One key pair of every algorithm this build offers besides the two admitted.
fn unsupported_keys() -> Vec<KeyPair> {
    vec![
        KeyPair::try_from_seed(vec![9; 32], Algorithm::Secp256k1).unwrap(),
        #[cfg(feature = "bls")]
        KeyPair::try_from_seed(vec![10; 32], Algorithm::BlsNormal).unwrap(),
        #[cfg(feature = "bls")]
        KeyPair::try_from_seed(vec![11; 32], Algorithm::BlsSmall).unwrap(),
    ]
}

#[test]
fn provider_keys_are_ed25519_or_mldsa65_only() {
    let message = b"provider message";
    for pair in [
        ed25519(1),
        #[cfg(feature = "pqc")]
        mldsa(1),
    ] {
        let signature = phone_control_provider_sign(pair.private_key(), message).unwrap();
        phone_control_provider_verify(pair.public_key(), message, &signature).unwrap();
    }
    let accepted = phone_control_provider_sign(ed25519(1).private_key(), message).unwrap();
    for pair in unsupported_keys() {
        assert_eq!(
            PhoneControlProviderKeyIdV1::commit(pair.public_key()).unwrap_err(),
            PhoneControlError::UnsupportedProviderKeyAlgorithm
        );
        assert_eq!(
            phone_control_provider_sign(pair.private_key(), message).unwrap_err(),
            PhoneControlError::UnsupportedProviderKeyAlgorithm
        );
        // A signature that is valid under the unsupported key is refused, and
        // so is any other signature presented with that key.
        let own = Signature::try_new(pair.private_key(), message).unwrap();
        own.verify(pair.public_key(), message).unwrap();
        for signature in [&own, &accepted] {
            assert_eq!(
                phone_control_provider_verify(pair.public_key(), message, signature),
                Err(PhoneControlError::UnsupportedProviderKeyAlgorithm)
            );
        }
    }
}

#[test]
fn provider_signature_binds_the_key_and_every_message_byte() {
    let message = b"iroha.ram_lfe.v1.phone_control.credential/frame".to_vec();
    for (pair, other) in [
        (ed25519(1), ed25519(2)),
        #[cfg(feature = "pqc")]
        (mldsa(1), mldsa(2)),
    ] {
        let signature = phone_control_provider_sign(pair.private_key(), &message).unwrap();
        phone_control_provider_verify(pair.public_key(), &message, &signature).unwrap();
        let rejected = |public_key: &PublicKey, message: &[u8], signature: &Signature| {
            assert_eq!(
                phone_control_provider_verify(public_key, message, signature),
                Err(PhoneControlError::BadProviderSignature)
            );
        };
        // Another key of the same algorithm.
        rejected(other.public_key(), &message, &signature);
        // Every byte of the message, a shorter and a longer message.
        for position in 0..message.len() {
            let mut altered = message.clone();
            altered[position] ^= 1;
            rejected(pair.public_key(), &altered, &signature);
        }
        rejected(pair.public_key(), &message[..message.len() - 1], &signature);
        rejected(
            pair.public_key(),
            &[&message[..], b"0"].concat(),
            &signature,
        );
        // A truncated, an extended, an empty and an all-zero signature.
        let bytes = signature.payload();
        rejected(
            pair.public_key(),
            &message,
            &Signature::from_bytes(&bytes[..bytes.len() - 1]),
        );
        rejected(
            pair.public_key(),
            &message,
            &Signature::from_bytes(&[bytes, &[0]].concat()),
        );
        rejected(pair.public_key(), &message, &Signature::from_bytes(&[]));
        rejected(
            pair.public_key(),
            &message,
            &Signature::from_bytes(&vec![0; bytes.len()]),
        );
        // One flipped bit of the signature.
        let mut flipped = bytes.to_vec();
        flipped[bytes.len() / 2] ^= 1;
        rejected(
            pair.public_key(),
            &message,
            &Signature::from_bytes(&flipped),
        );
    }
    #[cfg(feature = "pqc")]
    {
        // A signature of one algorithm never verifies under a key of the other.
        let (first, second) = (ed25519(1), mldsa(1));
        let by_first = phone_control_provider_sign(first.private_key(), &message).unwrap();
        let by_second = phone_control_provider_sign(second.private_key(), &message).unwrap();
        assert_eq!(
            phone_control_provider_verify(second.public_key(), &message, &by_first),
            Err(PhoneControlError::BadProviderSignature)
        );
        assert_eq!(
            phone_control_provider_verify(first.public_key(), &message, &by_second),
            Err(PhoneControlError::BadProviderSignature)
        );
    }
}

/// Canonical encoding of the identity of the Ed25519 group, a small-order point.
const IDENTITY_R: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[test]
fn ed25519_signatures_with_a_replaced_r_are_refused() {
    // A provider signature whose `R` is replaced by a non-canonical encoding
    // or by a small-order point is refused. This alone does not show that
    // verification is strict, because these signatures satisfy no equation;
    // the next test does.
    const NONCANONICAL_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    const SMALL_ORDER_R: [u8; 32] = IDENTITY_R;
    let pair = ed25519(1);
    let message = b"provider message";
    let signature = phone_control_provider_sign(pair.private_key(), message).unwrap();
    for replacement in [NONCANONICAL_R, SMALL_ORDER_R] {
        let mut bytes = signature.payload().to_vec();
        bytes[..32].copy_from_slice(&replacement);
        assert_eq!(
            phone_control_provider_verify(
                pair.public_key(),
                message,
                &Signature::from_bytes(&bytes)
            ),
            Err(PhoneControlError::BadProviderSignature)
        );
    }
}

#[test]
fn ed25519_signature_that_only_an_unchecked_verifier_accepts_is_refused() {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use ed25519_dalek::Verifier as _;
    use sha2::{Digest as _, Sha512};

    let pair = ed25519(1);
    let message = b"provider message";
    let (_, seed) = pair.private_key().to_bytes();
    let (_, public) = pair.public_key().to_bytes();
    let public: [u8; 32] = public.try_into().unwrap();

    // The signing scalar of the key, as RFC 8032 derives it from the seed.
    let expanded: [u8; 64] = Sha512::digest(seed).into();
    let mut clamped = [0_u8; 32];
    clamped.copy_from_slice(&expanded[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(clamped);
    assert_eq!(
        (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes(),
        public,
        "the derived scalar is the scalar of the provider key"
    );

    // With `R` the identity and `S = k * a`, the verification equation
    // `[S]B = R + [k]A` holds. Only the holder of the key can build this
    // signature, and it is a second signature of the same message: a verifier
    // that does not reject a small-order `R` accepts it and the regular one.
    let challenge = Scalar::from_bytes_mod_order_wide(
        &Sha512::new()
            .chain_update(IDENTITY_R)
            .chain_update(public)
            .chain_update(message)
            .finalize()
            .into(),
    );
    let forged = [IDENTITY_R, (challenge * scalar).to_bytes()].concat();

    // Control: the unchecked verifier of the backend accepts it, so the
    // refusal below is the strict rule and not a broken signature.
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
    let unchecked = ed25519_dalek::Signature::from_slice(&forged).unwrap();
    verifying.verify(message, &unchecked).unwrap();
    assert!(verifying.verify_strict(message, &unchecked).is_err());

    assert_eq!(
        phone_control_provider_verify(pair.public_key(), message, &Signature::from_bytes(&forged)),
        Err(PhoneControlError::BadProviderSignature)
    );
    // The regular signature of the same key over the same message is admitted.
    let regular = phone_control_provider_sign(pair.private_key(), message).unwrap();
    phone_control_provider_verify(pair.public_key(), message, &regular).unwrap();
}

#[cfg(feature = "pqc")]
#[test]
fn mldsa65_signatures_of_another_length_are_refused() {
    let pair = mldsa(1);
    let message = b"provider message";
    let signature = phone_control_provider_sign(pair.private_key(), message).unwrap();
    let bytes = signature.payload();
    phone_control_provider_verify(pair.public_key(), message, &signature).unwrap();
    for malformed in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes, &[0]].concat(),
        [bytes, bytes].concat(),
        Vec::new(),
    ] {
        assert_ne!(malformed.len(), bytes.len());
        assert_eq!(
            phone_control_provider_verify(
                pair.public_key(),
                message,
                &Signature::from_bytes(&malformed)
            ),
            Err(PhoneControlError::BadProviderSignature)
        );
    }
}

#[cfg(not(feature = "pqc"))]
#[test]
fn provider_mldsa_key_generation_reports_unavailable_backend() {
    let error = KeyPair::try_from_seed(vec![1; 32], Algorithm::MlDsa).unwrap_err();
    assert!(matches!(
        error,
        crate::Error::UnsupportedImplementation(crate::UnsupportedImplementation {
            algorithm: Algorithm::MlDsa,
            operation: crate::CryptoOperation::GenerateKeyPair
        })
    ));
}

#[test]
fn phone_control_domains_are_distinct_and_prefix_free_with_the_v1_tables() {
    let all: Vec<&[u8]> = RAM_LFE_V1_PUBLIC_DOMAINS
        .iter()
        .chain(&PHONE_CONTROL_V1_CRYPTO_DOMAINS)
        .copied()
        .collect();
    for (index, domain) in all.iter().enumerate() {
        assert!(domain.starts_with(b"iroha.ram_lfe.v1."));
        for (other_index, other) in all.iter().enumerate() {
            assert!(
                index == other_index || !other.starts_with(domain),
                "a domain must not be a prefix of another"
            );
        }
    }
    for domain in PHONE_CONTROL_V1_CRYPTO_DOMAINS {
        assert!(domain.starts_with(b"iroha.ram_lfe.v1.phone_control."));
        assert!(!RAM_LFE_V1_PRIVATE_CONTEXTS.contains(&std::str::from_utf8(domain).unwrap()));
    }
    // The typed Goldilocks domain of the number commitment is not a Blake2b
    // domain: its protocol label is a strict prefix of every Blake2b domain of
    // this contract and equals none.
    assert!(
        all.iter()
            .all(|domain| *domain != PHONE_CONTROL_V1_NUMBER_COMMITMENT_PROTOCOL.as_bytes())
    );
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

/// The row of the section that defines one frame, and the field names it
/// lists after the frame name, in order.
fn specified_frame<'a>(section: &'a str, frame: &str) -> (&'a str, Vec<&'a str>) {
    let marker = format!("`{frame}`: ");
    let mut rows = section.lines().filter(|line| line.contains(&marker));
    let row = rows
        .next()
        .unwrap_or_else(|| panic!("specification has no field row for {frame}"));
    assert!(
        rows.next().is_none(),
        "specification defines {frame} more than once"
    );
    let fields = row[row.find(&marker).unwrap() + marker.len()..]
        .split('|')
        .next()
        .unwrap();
    (row, fields.split('`').skip(1).step_by(2).collect())
}

#[test]
fn specification_field_order_is_the_crypto_frame_definitions() {
    let document = specification();
    let section = section(&document);
    // Every borrowed frame of this module is in the table its macro records.
    let defined = include_str!("phone_control.rs")
        .matches("\ncommitment_frame! {")
        .count();
    assert_eq!(defined, COMMITMENT_FRAMES.len());

    let (row, fields) = specified_frame(section, "PhoneControlProviderKeyInputV1");
    assert_eq!(fields, COMMITMENT_FRAMES[0].1);
    assert!(
        COMMITMENT_FRAMES[0]
            .0
            .ends_with("::PhoneControlProviderKeyInputV1")
    );
    assert!(row.contains("`iroha.ram_lfe.v1.phone_control.provider_key`"));

    let (_, fields) = specified_frame(section, "PhoneNumberCommitmentV1");
    assert_eq!(fields, schema_fields::<PhoneNumberCommitmentV1>());

    for domain in PHONE_CONTROL_V1_CRYPTO_DOMAINS {
        let domain = std::str::from_utf8(domain).unwrap();
        assert!(
            section.contains(&format!("`{domain}`")),
            "specification lacks domain {domain}"
        );
    }
}

/// The value cell of one row of the typed-domain table of the specification.
fn domain_cell<'a>(section: &'a str, field: &str) -> &'a str {
    let marker = "<!-- phone-control-number-commitment -->";
    let start = section
        .find(marker)
        .expect("specification carries the number-commitment table")
        + marker.len();
    section[start..]
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .find_map(|line| {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            (cells.len() == 2 && cells[0] == field).then_some(cells[1])
        })
        .unwrap_or_else(|| panic!("number-commitment table has no row {field}"))
}

fn first_backticked(cell: &str) -> &str {
    cell.split('`')
        .nth(1)
        .unwrap_or_else(|| panic!("cell names no value: {cell}"))
}

#[test]
fn specification_states_the_typed_domain_and_fields_the_code_hashes() {
    let document = specification();
    let section = section(&document);
    assert_eq!(
        first_backticked(domain_cell(section, "catalog")),
        FASTPQ_CATALOG_V1
    );
    assert_eq!(
        first_backticked(domain_cell(section, "protocol")),
        PHONE_CONTROL_V1_NUMBER_COMMITMENT_PROTOCOL
    );
    assert_eq!(
        first_backticked(domain_cell(section, "profile")),
        DIGEST.label()
    );
    assert_eq!(
        first_backticked(domain_cell(section, "role")),
        PHONE_CONTROL_V1_NUMBER_COMMITMENT_ROLE
    );
    assert_eq!(domain_cell(section, "phase"), "empty");
    assert_eq!(domain_cell(section, "level, index, counter"), "0");
    assert!(domain_cell(section, "field 0").starts_with("16 bytes"));
    assert!(domain_cell(section, "field 1").starts_with("32 bytes"));
    // The section names the one implemented digest and says it is unqualified.
    assert!(section.contains("`GoldilocksDigest384V1`"));
    assert!(section.contains("unqualified"));
    assert!(section.contains("(fastpq_compact_digest_security.md)"));
}
