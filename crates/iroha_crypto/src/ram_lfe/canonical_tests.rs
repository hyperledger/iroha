//! Canonical V1 commitments: framing, binding of every field, hiding and rotation invariance.

use super::*;
use crate::ram_lfe::{
    HiddenRamFheInstruction as Op,
    clearing::cleared_cells,
    initialization::INITIALIZATION_FRAME,
    reference::{RamLfeInitialMemoryV1, RamLfeOrderedOutputV1},
};

fn build(instructions: &[Op]) -> HiddenRamFheProgram {
    let mut builder = HiddenRamFheProgram::builder().unwrap();
    for &instruction in instructions {
        builder.push(instruction).unwrap();
    }
    builder.finish().unwrap()
}

fn key(byte: u8) -> RamLfeProgramKeyV1 {
    RamLfeProgramKeyV1::from_bytes([byte; 32]).unwrap()
}

const AFFINE_TAPE: [Op; 5] = [
    Op::LoadInput(0, 1),
    Op::LoadState(1, 3),
    Op::Add(2, 0, 1),
    Op::MulPlain(2, 2, 5),
    Op::Output(2),
];

fn affine_program() -> HiddenRamFheProgram {
    build(&AFFINE_TAPE)
}

fn limit() -> RamLfeQueryLimitV1 {
    RamLfeQueryLimitV1::new(1000, 3).unwrap()
}

fn commit(
    class: RamLfeClassV1,
    key_byte: u8,
    program: &HiddenRamFheProgram,
) -> RamLfeFunctionIdentityV1 {
    RamLfeFunctionIdentityV1::commit(class, &key(key_byte), program, limit()).unwrap()
}

fn identity() -> RamLfeFunctionIdentityV1 {
    commit(RamLfeClassV1::Affine, 7, &affine_program())
}

fn execution(seed: &[u8]) -> RamLfeExecutionContextIdV1 {
    RamLfeExecutionContextIdV1::commit(seed).unwrap()
}

fn policy() -> RamLfePolicyV1 {
    RamLfePolicyV1 {
        function: identity(),
        profile: RamLfeProfileIdV1::from_descriptor(b"profile").unwrap(),
        encryption_key: RamLfeEncryptionKeyCommitmentV1::commit(b"encryption").unwrap(),
        evaluation_key: RamLfeEvaluationKeyCommitmentV1::commit(b"evaluation").unwrap(),
        opening_key: RamLfeOpeningKeyCommitmentV1::commit(b"opening").unwrap(),
        prf_key: RamLfePrfKeyCommitmentV1::commit(b"prf").unwrap(),
        relation: RamLfeRelationIdV1::from_descriptor(b"relation").unwrap(),
    }
}

fn roundtrip<T>(value: &T)
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq + fmt::Debug,
{
    let frame = norito::encode_canonical(value).unwrap();
    assert_eq!(&norito::decode_canonical::<T>(&frame).unwrap(), value);
    // A truncated frame and a frame of another schema never decode to this type.
    assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
}

#[test]
fn every_canonical_type_roundtrips_through_norito() {
    let function = identity();
    let memory = RamLfeInitialMemoryV1::from_lanes(&[9; 32]).unwrap();
    let associated_data = RamLfeAssociatedDataHashV1::commit(b"context").unwrap();
    roundtrip(&function);
    roundtrip(&function.function);
    roundtrip(&function.initializer);
    roundtrip(&function.query_limit);
    roundtrip(&function.id().unwrap());
    roundtrip(&associated_data);
    roundtrip(&execution(b"execution"));
    roundtrip(
        &RamLfeInitializedMemoryCommitmentV1::commit(
            &key(7),
            function.id().unwrap(),
            associated_data,
            execution(b"execution"),
            &memory,
        )
        .unwrap(),
    );
    roundtrip(
        &RamLfeOutputCommitmentV1::commit(
            &RamLfeOrderedOutputV1::from_scalars(&[1, 256]).unwrap(),
            &RamLfeOutputBlindingV1::from_bytes([3; 32]).unwrap(),
        )
        .unwrap(),
    );
    let policy = policy();
    roundtrip(&policy);
    roundtrip(&policy.profile);
    roundtrip(&policy.encryption_key);
    roundtrip(&policy.evaluation_key);
    roundtrip(&policy.opening_key);
    roundtrip(&policy.prf_key);
    roundtrip(&policy.relation);
    roundtrip(&policy.commitment().unwrap());
    roundtrip(&RamLfeInputCiphertextCommitmentV1::commit(b"input").unwrap());
    roundtrip(&RamLfeOutputCiphertextCommitmentV1::commit(b"output").unwrap());
}

#[test]
fn domains_and_contexts_are_distinct_and_prefix_free() {
    for (index, domain) in RAM_LFE_V1_PUBLIC_DOMAINS.iter().enumerate() {
        assert!(domain.starts_with(b"iroha.ram_lfe.v1."));
        for (other_index, other) in RAM_LFE_V1_PUBLIC_DOMAINS.iter().enumerate() {
            assert!(
                index == other_index || !other.starts_with(domain),
                "a domain must not be a prefix of another"
            );
        }
    }
    for (index, context) in RAM_LFE_V1_PRIVATE_CONTEXTS.iter().enumerate() {
        assert!(context.starts_with("iroha.ram_lfe.v1."));
        assert!(!RAM_LFE_V1_PRIVATE_CONTEXTS[..index].contains(context));
        assert!(!RAM_LFE_V1_PUBLIC_DOMAINS.contains(&context.as_bytes()));
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

fn short_name(frame: &str) -> &str {
    frame.rsplit("::").next().unwrap()
}

/// The row of the specification that defines one frame, and the field names
/// it lists after the frame name, in order.
fn specified_frame<'a>(document: &'a str, frame: &str) -> (&'a str, Vec<&'a str>) {
    let marker = format!("`{frame}`: ");
    let mut rows = document.lines().filter(|line| line.contains(&marker));
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

/// The specification with Unix line endings, whatever the checkout wrote.
fn specification() -> String {
    crate::ram_lfe::specification_tests::repository_file("specs/ram_lfe_execution_proof.md")
}

#[test]
fn specification_lists_every_domain_and_context() {
    let document = specification();
    let listed = |name: &str| document.contains(&format!("`{name}`"));
    for domain in RAM_LFE_V1_PUBLIC_DOMAINS {
        let domain = std::str::from_utf8(domain).unwrap();
        assert!(listed(domain), "specification lacks domain {domain}");
    }
    for context in RAM_LFE_V1_PRIVATE_CONTEXTS {
        assert!(listed(context), "specification lacks context {context}");
    }
}

/// The sentence of the specification that defines the digest of a committed byte
/// string, compared with what the byte-string commitments hash.
#[test]
fn specification_states_the_digest_that_byte_strings_are_committed_with() {
    use blake2::{
        Blake2b,
        digest::{Digest as _, consts::U32},
    };

    let document = specification();
    let start = document
        .find("A byte string is committed through the last row:")
        .expect("specification defines how a byte string is committed");
    let paragraph: String = document[start..]
        .split("\n\n")
        .next()
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        paragraph.contains(
            "`length` is a u64 and `digest` is the Iroha Blake2b-256 `Hash` of the bytes, \
             with the low bit of its last byte set (`Hash::new`); it is not the unmarked \
             Blake2b output."
        ),
        "the specification must state the digest the code commits: {paragraph}"
    );
    assert!(
        !document.contains("plain Blake2b"),
        "no committed digest is the unmarked Blake2b output"
    );

    // The code: `Hash::new` is Blake2b-256 with the low bit of the last byte set. A byte
    // string whose unmarked digest has that bit clear tells the two apart.
    let unmarked = |bytes: &[u8]| -> [u8; 32] { Blake2b::<U32>::digest(bytes).into() };
    let bytes = (0_u8..=u8::MAX)
        .map(|byte| [byte; 3])
        .find(|bytes| unmarked(bytes)[31] & 1 == 0)
        .expect("some three-byte string has an unmarked digest with a clear low bit");
    let plain = unmarked(&bytes);
    let mut marked = plain;
    marked[31] |= 1;
    assert_ne!(plain, marked);
    assert_eq!(Hash::new(bytes).as_ref(), &marked);

    // The frame of the last row holds the length and the marked digest, never the
    // unmarked one, and every byte-string role commits exactly that frame under its
    // own domain.
    let frame = norito::encode_canonical(&OpaqueBytesInputV1 {
        length: 3,
        digest: Hash::new(bytes),
    })
    .unwrap();
    let holds = |digest: &[u8; 32]| frame.windows(32).any(|window| window == digest);
    assert!(holds(&marked) && !holds(&plain));
    let expected = |domain: &[u8]| public_digest(domain, &frame);
    let committed: [(&[u8], Hash); 10] = [
        (
            PROFILE_DOMAIN,
            *RamLfeProfileIdV1::from_descriptor(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            RELATION_DOMAIN,
            *RamLfeRelationIdV1::from_descriptor(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            ENCRYPTION_KEY_DOMAIN,
            *RamLfeEncryptionKeyCommitmentV1::commit(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            EVALUATION_KEY_DOMAIN,
            *RamLfeEvaluationKeyCommitmentV1::commit(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            OPENING_KEY_DOMAIN,
            *RamLfeOpeningKeyCommitmentV1::commit(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            PRF_KEY_DOMAIN,
            *RamLfePrfKeyCommitmentV1::commit(&bytes).unwrap().as_hash(),
        ),
        (
            INPUT_CIPHERTEXT_DOMAIN,
            *RamLfeInputCiphertextCommitmentV1::commit(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            OUTPUT_CIPHERTEXT_DOMAIN,
            *RamLfeOutputCiphertextCommitmentV1::commit(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            ASSOCIATED_DATA_DOMAIN,
            *RamLfeAssociatedDataHashV1::commit(&bytes)
                .unwrap()
                .as_hash(),
        ),
        (
            EXECUTION_CONTEXT_DOMAIN,
            *RamLfeExecutionContextIdV1::commit(&bytes)
                .unwrap()
                .as_hash(),
        ),
    ];
    for (domain, commitment) in committed {
        assert_eq!(
            commitment,
            expected(domain),
            "{}",
            String::from_utf8_lossy(domain)
        );
    }
}

#[test]
fn specification_field_order_is_the_frame_definitions() {
    let document = specification();
    // Every borrowed frame of this module is in the table its macro records.
    let defined = include_str!("canonical.rs")
        .matches("\ncommitment_frame! {")
        .count();
    assert_eq!(defined, COMMITMENT_FRAMES.len());

    let owned = |fields: &[&str]| fields.iter().map(|&field| field.to_owned()).collect();
    // The domain or context each frame is hashed under, with the field order
    // taken from the definition itself.
    let frames: Vec<(&str, &str, Vec<String>)> = vec![
        (
            "",
            short_name(COMMITMENT_FRAMES[0].0),
            owned(COMMITMENT_FRAMES[0].1),
        ),
        (
            "iroha.ram_lfe.v1.function_commitment",
            short_name(COMMITMENT_FRAMES[1].0),
            owned(COMMITMENT_FRAMES[1].1),
        ),
        (
            "iroha.ram_lfe.v1.initializer_key",
            short_name(COMMITMENT_FRAMES[2].0),
            owned(COMMITMENT_FRAMES[2].1),
        ),
        (
            "iroha.ram_lfe.v1.initial_state",
            short_name(INITIALIZATION_FRAME.0),
            owned(INITIALIZATION_FRAME.1),
        ),
        (
            "iroha.ram_lfe.v1.memory_blinding",
            short_name(COMMITMENT_FRAMES[3].0),
            owned(COMMITMENT_FRAMES[3].1),
        ),
        (
            "iroha.ram_lfe.v1.initialized_memory",
            short_name(COMMITMENT_FRAMES[4].0),
            owned(COMMITMENT_FRAMES[4].1),
        ),
        (
            "iroha.ram_lfe.v1.ordered_output",
            short_name(COMMITMENT_FRAMES[5].0),
            owned(COMMITMENT_FRAMES[5].1),
        ),
        (
            "iroha.ram_lfe.v1.function_identity",
            "RamLfeFunctionIdentityV1",
            schema_fields::<RamLfeFunctionIdentityV1>(),
        ),
        (
            "",
            "RamLfeQueryLimitV1",
            schema_fields::<RamLfeQueryLimitV1>(),
        ),
        (
            "iroha.ram_lfe.v1.policy",
            "RamLfePolicyV1",
            schema_fields::<RamLfePolicyV1>(),
        ),
    ];
    for (domain, frame, fields) in &frames {
        let (row, specified) = specified_frame(&document, frame);
        assert_eq!(&specified, fields, "field order of {frame}");
        assert!(!fields.is_empty());
        assert!(
            domain.is_empty() || row.contains(&format!("`{domain}`")),
            "the row of {frame} must name {domain}"
        );
    }
    for context in RAM_LFE_V1_PRIVATE_CONTEXTS {
        assert!(
            frames.iter().any(|(domain, ..)| domain == &context),
            "context {context} has no frame row"
        );
    }

    // No other frame is specified: every `RamLfe…V1`: marker is one of the
    // frames above or one of the data model's four records, which the data
    // model's own test compares with their definitions.
    let model = [
        "RamLfeExecutionContextV1",
        "RamLfeReplayV1",
        "RamLfeReceiptV1",
        "RamLfeOpeningV1",
    ];
    let mut markers = 0;
    for piece in document.split("`: ") {
        let name = piece.rsplit('`').next().unwrap();
        if name.starts_with("RamLfe") && name.ends_with("V1") {
            markers += 1;
            assert!(
                frames.iter().any(|(_, frame, _)| frame == &name) || model.contains(&name),
                "specification defines an unknown frame {name}"
            );
        }
    }
    assert_eq!(markers, frames.len() + model.len());
}

#[test]
fn secrets_are_validated_redacted_and_generated_fresh() {
    assert_eq!(
        RamLfeProgramKeyV1::from_bytes([0; 32]).unwrap_err(),
        RamLfeError::InvalidCanonicalValue("program key must not be all zero")
    );
    assert_eq!(
        RamLfeOutputBlindingV1::from_bytes([0; 32]).unwrap_err(),
        RamLfeError::InvalidCanonicalValue("output blinding must not be all zero")
    );
    // One nonzero byte anywhere is enough: the zero check covers every byte.
    for position in [0, 31] {
        let mut bytes = [0; 32];
        bytes[position] = 1;
        assert_eq!(
            RamLfeProgramKeyV1::from_bytes(bytes).unwrap().expose(),
            &bytes
        );
    }
    assert_eq!(format!("{:?}", key(0xA5)), "[REDACTED RAM-LFE program key]");
    assert_eq!(
        format!(
            "{:?}",
            RamLfeOutputBlindingV1::from_bytes([0xA5; 32]).unwrap()
        ),
        "[REDACTED RAM-LFE output blinding]"
    );
    assert_eq!(RamLfeProgramKeyV1::LENGTH, 32);
    #[cfg(feature = "rand")]
    {
        let first = RamLfeProgramKeyV1::generate().unwrap();
        let second = RamLfeProgramKeyV1::generate().unwrap();
        assert_ne!(first.expose(), second.expose());
        assert_ne!(first.expose(), &[0; 32]);
        let blinding = RamLfeOutputBlindingV1::generate().unwrap();
        assert_ne!(blinding.expose(), &[0; 32]);
    }
}

#[test]
fn secret_owners_keep_one_address_and_clear_on_success_error_and_unwind() {
    // A move of the owner moves a pointer: the secret bytes stay where they are.
    let owner = key(0xA5);
    let address = owner.expose().as_ptr();
    let moved = Box::new(std::convert::identity(owner));
    assert_eq!(moved.expose().as_ptr(), address);
    let blinding = RamLfeOutputBlindingV1::from_bytes([0x5A; 32]).unwrap();
    let address = blinding.expose().as_ptr();
    let moved_blinding = Some(blinding);
    assert_eq!(moved_blinding.as_ref().unwrap().expose().as_ptr(), address);

    // Success: both owners clear their 32 bytes when they drop.
    let before = cleared_cells();
    drop(moved);
    drop(moved_blinding);
    assert_eq!(cleared_cells() - before, 64);

    // Success through the commitments that borrow them. The memory commitment
    // also clears the 32-byte blinding it derives; the key and the 32 lanes
    // clear when their owners drop.
    let before = cleared_cells();
    {
        let key = key(7);
        let function = RamLfeFunctionIdentityV1::commit(
            RamLfeClassV1::Affine,
            &key,
            &affine_program(),
            limit(),
        )
        .unwrap();
        let memory = RamLfeInitialMemoryV1::from_lanes(&[9; 32]).unwrap();
        RamLfeInitializedMemoryCommitmentV1::commit(
            &key,
            function.id().unwrap(),
            RamLfeAssociatedDataHashV1::commit(b"context").unwrap(),
            execution(b"execution"),
            &memory,
        )
        .unwrap();
    }
    assert_eq!(cleared_cells() - before, 32 + 32 + 32);

    // Error: the all-zero import is rejected and its allocation is cleared.
    let before = cleared_cells();
    assert!(RamLfeProgramKeyV1::from_bytes([0; 32]).is_err());
    assert!(RamLfeOutputBlindingV1::from_bytes([0; 32]).is_err());
    assert_eq!(cleared_cells() - before, 64);

    // Error: a commitment that fails still clears the key it borrowed.
    let before = cleared_cells();
    let failing = || {
        let key = key(7);
        let multiplying = build(&[Op::LoadInput(0, 1), Op::Mul(0, 0, 0), Op::Output(0)]);
        RamLfeFunctionIdentityV1::commit(RamLfeClassV1::Affine, &key, &multiplying, limit())
    };
    assert!(failing().is_err());
    assert_eq!(cleared_cells() - before, 32);

    // Unwind: a panic while the owners are live clears them.
    let before = cleared_cells();
    assert!(
        std::panic::catch_unwind(|| {
            let _key = key(7);
            let _blinding = RamLfeOutputBlindingV1::from_bytes([3; 32]).unwrap();
            panic!("secret owner unwind control");
        })
        .is_err()
    );
    assert_eq!(cleared_cells() - before, 64);
}

// Independent owned shapes with the declared frame identities reproduce each
// commitment from first principles.
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::RamLfeFunctionCommitmentInputV1",
    frame = "iroha_crypto::ram_lfe::RamLfeFunctionCommitmentInputV1"
)]
struct OwnedFunctionCommitmentInput {
    plaintext_semantics: Hash,
    class: RamLfeClassV1,
    program_key: Vec<u8>,
    instruction_count: u16,
    tape: Vec<u8>,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::RamLfeInitializerKeyInputV1",
    frame = "iroha_crypto::ram_lfe::RamLfeInitializerKeyInputV1"
)]
struct OwnedInitializerKeyInput {
    plaintext_semantics: Hash,
    class: RamLfeClassV1,
    function_commitment: Vec<u8>,
    program_key: Vec<u8>,
}

fn blake3_commitment<T: norito::NoritoSerialize>(context: &str, value: &T) -> [u8; 32] {
    let frame = norito::encode_canonical(value).unwrap();
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&frame);
    *hasher.finalize().as_bytes()
}

fn tape_bytes(instructions: &[Op]) -> Vec<u8> {
    instructions
        .iter()
        .flat_map(|&instruction| crate::ram_lfe::program::instruction_fields(instruction))
        .flat_map(u64::to_le_bytes)
        .collect()
}

#[test]
fn function_identity_is_the_documented_framing() {
    let identity = identity();
    let semantics = ram_lfe_v1_plaintext_semantics_hash();
    assert_eq!(identity.class, RamLfeClassV1::Affine);
    assert_eq!(identity.plaintext_semantics, semantics);
    assert_eq!(identity.query_limit, limit());
    let function = blake3_commitment(
        "iroha.ram_lfe.v1.function_commitment",
        &OwnedFunctionCommitmentInput {
            plaintext_semantics: semantics,
            class: RamLfeClassV1::Affine,
            program_key: vec![7; 32],
            instruction_count: 5,
            tape: tape_bytes(&AFFINE_TAPE),
        },
    );
    assert_eq!(identity.function.as_bytes(), &function);
    assert_eq!(
        identity.initializer.as_bytes(),
        &blake3_commitment(
            "iroha.ram_lfe.v1.initializer_key",
            &OwnedInitializerKeyInput {
                plaintext_semantics: semantics,
                class: RamLfeClassV1::Affine,
                function_commitment: function.to_vec(),
                program_key: vec![7; 32],
            }
        )
    );
    let frame = norito::encode_canonical(&identity).unwrap();
    assert_eq!(
        identity.id().unwrap().as_hash(),
        &Hash::new([b"iroha.ram_lfe.v1.function_identity".as_slice(), &frame].concat())
    );
}

#[test]
fn function_identity_binds_class_key_limit_and_every_tape_instruction() {
    let base = identity();
    let base_id = base.id().unwrap();
    // Same inputs, same identity.
    assert_eq!(base, identity());

    // Class: the same tape and key under another class is another function,
    // and its initializer commitment differs too.
    let bounded = commit(RamLfeClassV1::Bounded, 7, &affine_program());
    assert_ne!(bounded.function, base.function);
    assert_ne!(bounded.initializer, base.initializer);
    assert_ne!(bounded.id().unwrap(), base_id);

    // Program key: both commitments change, so an unkeyed guess of the tape fails.
    let rekeyed = commit(RamLfeClassV1::Affine, 8, &affine_program());
    assert_ne!(rekeyed.function, base.function);
    assert_ne!(rekeyed.initializer, base.initializer);
    assert_ne!(rekeyed.id().unwrap(), base_id);

    // Tape: every changed, added, removed or reordered instruction changes
    // both commitments.
    let variants: [&[Op]; 5] = [
        &[
            Op::LoadInput(0, 2),
            Op::LoadState(1, 3),
            Op::Add(2, 0, 1),
            Op::MulPlain(2, 2, 5),
            Op::Output(2),
        ],
        &[
            Op::LoadInput(0, 1),
            Op::LoadState(1, 3),
            Op::Add(2, 0, 1),
            Op::MulPlain(2, 2, 6),
            Op::Output(2),
        ],
        &[
            Op::LoadInput(0, 1),
            Op::LoadState(1, 3),
            Op::Add(2, 0, 1),
            Op::MulPlain(2, 2, 5),
            Op::Output(2),
            Op::Output(2),
        ],
        &[
            Op::LoadInput(0, 1),
            Op::LoadState(1, 3),
            Op::Add(2, 0, 1),
            Op::Output(2),
        ],
        &[
            Op::LoadState(1, 3),
            Op::LoadInput(0, 1),
            Op::Add(2, 0, 1),
            Op::MulPlain(2, 2, 5),
            Op::Output(2),
        ],
    ];
    let mut functions = std::collections::BTreeSet::from([base.function]);
    let mut initializers = std::collections::BTreeSet::from([base.initializer]);
    for tape in variants {
        let variant = commit(RamLfeClassV1::Affine, 7, &build(tape));
        assert!(functions.insert(variant.function), "tape must be bound");
        assert!(
            initializers.insert(variant.initializer),
            "initializer must differ for every function"
        );
        assert_ne!(variant.id().unwrap(), base_id);
    }

    // Query limit: it is a public field of the record, so it changes the
    // identity and leaves the two hiding commitments as they are.
    for other in [
        RamLfeQueryLimitV1::new(1001, 3).unwrap(),
        RamLfeQueryLimitV1::new(1000, 4).unwrap(),
    ] {
        let relimited = RamLfeFunctionIdentityV1::commit(
            RamLfeClassV1::Affine,
            &key(7),
            &affine_program(),
            other,
        )
        .unwrap();
        assert_eq!(relimited.function, base.function);
        assert_eq!(relimited.initializer, base.initializer);
        assert_ne!(relimited.id().unwrap(), base_id);
    }

    // Each public field of the record is bound by the identity digest.
    let mut other_semantics = base;
    other_semantics.plaintext_semantics = Hash::new(b"other semantics");
    assert_eq!(
        other_semantics.id().unwrap_err(),
        RamLfeError::InvalidCanonicalValue("function identity names unknown plaintext semantics")
    );
    for mutated in [
        RamLfeFunctionIdentityV1 {
            class: RamLfeClassV1::Refresh,
            ..base
        },
        RamLfeFunctionIdentityV1 {
            function: rekeyed.function,
            ..base
        },
        RamLfeFunctionIdentityV1 {
            initializer: rekeyed.initializer,
            ..base
        },
    ] {
        assert_ne!(mutated.id().unwrap(), base_id);
    }
}

#[test]
fn reusing_a_program_key_for_two_functions_is_not_visible_in_any_commitment() {
    // One key, two tapes and two classes: three function identities.
    let first = identity();
    let second = commit(
        RamLfeClassV1::Affine,
        7,
        &build(&[Op::LoadInput(0, 1), Op::Output(0)]),
    );
    let third = commit(RamLfeClassV1::Bounded, 7, &affine_program());
    let commitments: std::collections::BTreeSet<[u8; 32]> = [first, second, third]
        .iter()
        .flat_map(|identity| {
            [
                *identity.function.as_bytes(),
                *identity.initializer.as_bytes(),
            ]
        })
        .collect();
    // No commitment of one identity equals any commitment of another.
    assert_eq!(commitments.len(), 6);
    // The same class, key, tape and limit is the same identity everywhere.
    assert_eq!(first, identity());
}

#[test]
fn function_identity_requires_class_membership_and_opens_only_to_its_inputs() {
    let multiplying = build(&[Op::LoadInput(0, 1), Op::Mul(0, 0, 0), Op::Output(0)]);
    assert_eq!(
        RamLfeFunctionIdentityV1::commit(RamLfeClassV1::Affine, &key(7), &multiplying, limit())
            .unwrap_err(),
        RamLfeError::InstructionOutsideClass {
            class: RamLfeClassV1::Affine,
            instruction: 1,
            opcode: crate::RamLfeOpcodeV1::Mul,
        }
    );
    let identity = identity();
    identity.verify_opening(&key(7), &affine_program()).unwrap();
    assert_eq!(
        identity.verify_opening(&key(8), &affine_program()),
        Err(RamLfeError::CommitmentMismatch)
    );
    assert_eq!(
        identity.verify_opening(&key(7), &build(&[Op::LoadInput(0, 1), Op::Output(0)])),
        Err(RamLfeError::CommitmentMismatch)
    );
    // The declared class is part of what is opened.
    let relabelled = RamLfeFunctionIdentityV1 {
        class: RamLfeClassV1::Bounded,
        ..identity
    };
    assert_eq!(
        relabelled.verify_opening(&key(7), &affine_program()),
        Err(RamLfeError::CommitmentMismatch)
    );
    // An initializer taken from another function does not open.
    let transplanted = RamLfeFunctionIdentityV1 {
        initializer: commit(RamLfeClassV1::Bounded, 7, &affine_program()).initializer,
        ..identity
    };
    assert_eq!(
        transplanted.verify_opening(&key(7), &affine_program()),
        Err(RamLfeError::CommitmentMismatch)
    );
}

#[test]
fn query_limit_rejects_zero_and_inverted_limits_everywhere() {
    let invalid = [
        (0, 1, "query limit total must not be zero"),
        (1, 0, "query limit per beneficiary must not be zero"),
        (0, 0, "query limit total must not be zero"),
        (2, 3, "query limit per beneficiary exceeds the total"),
    ];
    for (total, per_beneficiary, message) in invalid {
        let error = RamLfeError::InvalidCanonicalValue(message);
        assert_eq!(
            RamLfeQueryLimitV1::new(total, per_beneficiary).unwrap_err(),
            error
        );
        // A decoded record carries the same rule: it cannot be committed,
        // identified, opened or placed in a policy.
        let decoded = RamLfeQueryLimitV1 {
            total,
            per_beneficiary,
        };
        assert_eq!(decoded.validate().unwrap_err(), error);
        assert_eq!(
            RamLfeFunctionIdentityV1::commit(
                RamLfeClassV1::Affine,
                &key(7),
                &affine_program(),
                decoded
            )
            .unwrap_err(),
            error
        );
        let function = RamLfeFunctionIdentityV1 {
            query_limit: decoded,
            ..identity()
        };
        assert_eq!(function.validate().unwrap_err(), error);
        assert_eq!(function.id().unwrap_err(), error);
        assert_eq!(
            function
                .verify_opening(&key(7), &affine_program())
                .unwrap_err(),
            error
        );
        let policy = RamLfePolicyV1 {
            function,
            ..policy()
        };
        assert_eq!(policy.validate().unwrap_err(), error);
        assert_eq!(policy.commitment().unwrap_err(), error);
    }
    // The smallest and the largest limits are valid.
    for (total, per_beneficiary) in [
        (1, 1),
        (u64::MAX, u32::MAX),
        (u64::from(u32::MAX), u32::MAX),
    ] {
        let limit = RamLfeQueryLimitV1::new(total, per_beneficiary).unwrap();
        assert_eq!(
            (limit.total, limit.per_beneficiary),
            (total, per_beneficiary)
        );
    }
}

#[test]
fn query_limit_charges_each_receipt_and_each_opening_once_until_exhausted() {
    let limit = RamLfeQueryLimitV1::new(3, 2).unwrap();
    // Receipts: exactly `total` are accepted over the lifetime.
    let mut accepted = 0;
    for expected in 1..=3 {
        accepted = limit.charge_receipt(accepted).unwrap();
        assert_eq!(accepted, expected);
    }
    assert_eq!(
        limit.charge_receipt(accepted),
        Err(RamLfeError::ReceiptLimitExhausted { limit: 3 })
    );
    // A persisted count above the limit never admits another receipt.
    assert_eq!(
        limit.charge_receipt(u64::MAX),
        Err(RamLfeError::ReceiptLimitExhausted { limit: 3 })
    );
    // Openings: exactly `per_beneficiary` for one beneficiary; another
    // beneficiary has its own count.
    let mut first = 0;
    for expected in 1..=2 {
        first = limit.charge_opening(first).unwrap();
        assert_eq!(first, expected);
    }
    assert_eq!(
        limit.charge_opening(first),
        Err(RamLfeError::BeneficiaryOpeningLimitExhausted { limit: 2 })
    );
    assert_eq!(limit.charge_opening(0), Ok(1));
    assert_eq!(
        limit.charge_opening(u32::MAX),
        Err(RamLfeError::BeneficiaryOpeningLimitExhausted { limit: 2 })
    );
    // The largest limits charge their last unit without overflow.
    let largest = RamLfeQueryLimitV1::new(u64::MAX, u32::MAX).unwrap();
    assert_eq!(largest.charge_receipt(u64::MAX - 1), Ok(u64::MAX));
    assert_eq!(largest.charge_opening(u32::MAX - 1), Ok(u32::MAX));
    assert!(largest.charge_receipt(u64::MAX).is_err());
    assert!(largest.charge_opening(u32::MAX).is_err());
}

#[test]
fn output_leakage_bound_is_the_exact_size_of_one_output_times_the_total() {
    // 257^64 as little-endian 32-bit limbs.
    let mut limbs = vec![1_u32];
    for _ in 0..crate::RAM_LFE_V1_MAX_OUTPUTS {
        let mut carry = 0_u64;
        for limb in &mut limbs {
            let product = u64::from(*limb) * u64::from(crate::RAM_LFE_V1_PLAINTEXT_MODULUS) + carry;
            *limb = u32::try_from(product & u64::from(u32::MAX)).unwrap();
            carry = product >> 32;
        }
        if carry != 0 {
            limbs.push(u32::try_from(carry).unwrap());
        }
    }
    let bits =
        u32::try_from(limbs.len() - 1).unwrap() * 32 + (32 - limbs.last().unwrap().leading_zeros());
    // 2^512 <= 257^64 < 2^513: one output is strictly less than 513 bits.
    assert_eq!(bits, 513);
    assert_eq!(RAM_LFE_V1_OUTPUT_LEAKAGE_BITS, bits);

    assert_eq!(
        RamLfeQueryLimitV1::new(1, 1)
            .unwrap()
            .output_leakage_bound_bits(),
        513
    );
    assert_eq!(limit().output_leakage_bound_bits(), 513_000);
    assert_eq!(
        RamLfeQueryLimitV1::new(u64::MAX, 1)
            .unwrap()
            .output_leakage_bound_bits(),
        u128::from(u64::MAX) * 513
    );
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::RamLfeOpaqueBytesInputV1",
    frame = "iroha_crypto::ram_lfe::RamLfeOpaqueBytesInputV1"
)]
struct OwnedOpaqueBytesInput {
    length: u64,
    digest: Hash,
}

fn opaque(domain: &[u8], bytes: &[u8]) -> Hash {
    let frame = norito::encode_canonical(&OwnedOpaqueBytesInput {
        length: bytes.len() as u64,
        digest: Hash::new(bytes),
    })
    .unwrap();
    Hash::new([domain, &frame].concat())
}

#[test]
fn byte_commitments_are_role_separated_and_reject_empty_material() {
    let material = b"identical canonical bytes";
    let digests = [
        *RamLfeProfileIdV1::from_descriptor(material)
            .unwrap()
            .as_hash(),
        *RamLfeRelationIdV1::from_descriptor(material)
            .unwrap()
            .as_hash(),
        *RamLfeEncryptionKeyCommitmentV1::commit(material)
            .unwrap()
            .as_hash(),
        *RamLfeEvaluationKeyCommitmentV1::commit(material)
            .unwrap()
            .as_hash(),
        *RamLfeOpeningKeyCommitmentV1::commit(material)
            .unwrap()
            .as_hash(),
        *RamLfePrfKeyCommitmentV1::commit(material)
            .unwrap()
            .as_hash(),
        *RamLfeInputCiphertextCommitmentV1::commit(material)
            .unwrap()
            .as_hash(),
        *RamLfeOutputCiphertextCommitmentV1::commit(material)
            .unwrap()
            .as_hash(),
        *RamLfeAssociatedDataHashV1::commit(material)
            .unwrap()
            .as_hash(),
        *RamLfeExecutionContextIdV1::commit(material)
            .unwrap()
            .as_hash(),
    ];
    let domains: [&[u8]; 10] = [
        b"iroha.ram_lfe.v1.profile",
        b"iroha.ram_lfe.v1.relation",
        b"iroha.ram_lfe.v1.key.encryption",
        b"iroha.ram_lfe.v1.key.evaluation",
        b"iroha.ram_lfe.v1.key.opening",
        b"iroha.ram_lfe.v1.key.prf",
        b"iroha.ram_lfe.v1.ciphertext.input",
        b"iroha.ram_lfe.v1.ciphertext.output",
        b"iroha.ram_lfe.v1.associated_data",
        b"iroha.ram_lfe.v1.execution_context",
    ];
    // The same bytes under two roles never give the same commitment.
    assert_eq!(
        digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        digests.len()
    );
    for (digest, domain) in digests.iter().zip(domains) {
        assert_eq!(*digest, opaque(domain, material));
        assert!(RAM_LFE_V1_PUBLIC_DOMAINS.contains(&domain));
    }
    // One changed or appended byte changes the commitment.
    assert_ne!(
        RamLfeEncryptionKeyCommitmentV1::commit(b"key-a").unwrap(),
        RamLfeEncryptionKeyCommitmentV1::commit(b"key-b").unwrap()
    );
    assert_ne!(
        RamLfeEncryptionKeyCommitmentV1::commit(b"key-a").unwrap(),
        RamLfeEncryptionKeyCommitmentV1::commit(b"key-a\0").unwrap()
    );

    let empty = |result: Result<Hash, RamLfeError>| {
        assert!(matches!(result, Err(RamLfeError::InvalidCanonicalValue(_))));
    };
    empty(RamLfeProfileIdV1::from_descriptor(b"").map(|value| *value.as_hash()));
    empty(RamLfeRelationIdV1::from_descriptor(b"").map(|value| *value.as_hash()));
    empty(RamLfeEncryptionKeyCommitmentV1::commit(b"").map(|value| *value.as_hash()));
    empty(RamLfeEvaluationKeyCommitmentV1::commit(b"").map(|value| *value.as_hash()));
    empty(RamLfeOpeningKeyCommitmentV1::commit(b"").map(|value| *value.as_hash()));
    empty(RamLfePrfKeyCommitmentV1::commit(b"").map(|value| *value.as_hash()));
    empty(RamLfeInputCiphertextCommitmentV1::commit(b"").map(|value| *value.as_hash()));
    empty(RamLfeOutputCiphertextCommitmentV1::commit(b"").map(|value| *value.as_hash()));
    empty(RamLfeExecutionContextIdV1::commit(b"").map(|value| *value.as_hash()));
}

#[test]
fn associated_data_is_bounded_and_may_be_empty() {
    let empty = RamLfeAssociatedDataHashV1::commit(b"").unwrap();
    assert_eq!(
        *empty.as_hash(),
        opaque(b"iroha.ram_lfe.v1.associated_data", b"")
    );
    assert_ne!(empty, RamLfeAssociatedDataHashV1::commit(b"\0").unwrap());
    assert!(RamLfeAssociatedDataHashV1::commit(&[1; 512]).is_ok());
    assert_eq!(
        RamLfeAssociatedDataHashV1::commit(&[1; 513]).unwrap_err(),
        RamLfeError::InvalidCanonicalValue("associated data exceeds 512 bytes")
    );
}

#[test]
fn policy_commitment_binds_every_field() {
    let base = policy();
    let commitment = base.commitment().unwrap();
    assert_eq!(commitment, policy().commitment().unwrap());
    let frame = norito::encode_canonical(&base).unwrap();
    assert_eq!(
        commitment.as_hash(),
        &Hash::new([b"iroha.ram_lfe.v1.policy".as_slice(), &frame].concat())
    );

    let other_function = commit(RamLfeClassV1::Affine, 8, &affine_program());
    let substitutions: [(&str, RamLfePolicyV1); 12] = [
        (
            "class",
            RamLfePolicyV1 {
                function: RamLfeFunctionIdentityV1 {
                    class: RamLfeClassV1::Bounded,
                    ..base.function
                },
                ..base
            },
        ),
        (
            "function commitment",
            RamLfePolicyV1 {
                function: RamLfeFunctionIdentityV1 {
                    function: other_function.function,
                    ..base.function
                },
                ..base
            },
        ),
        (
            "initializer commitment",
            RamLfePolicyV1 {
                function: RamLfeFunctionIdentityV1 {
                    initializer: other_function.initializer,
                    ..base.function
                },
                ..base
            },
        ),
        (
            "query limit total",
            RamLfePolicyV1 {
                function: RamLfeFunctionIdentityV1 {
                    query_limit: RamLfeQueryLimitV1::new(1001, 3).unwrap(),
                    ..base.function
                },
                ..base
            },
        ),
        (
            "query limit per beneficiary",
            RamLfePolicyV1 {
                function: RamLfeFunctionIdentityV1 {
                    query_limit: RamLfeQueryLimitV1::new(1000, 4).unwrap(),
                    ..base.function
                },
                ..base
            },
        ),
        (
            "function identity",
            RamLfePolicyV1 {
                function: other_function,
                ..base
            },
        ),
        (
            "profile",
            RamLfePolicyV1 {
                profile: RamLfeProfileIdV1::from_descriptor(b"other profile").unwrap(),
                ..base
            },
        ),
        (
            "encryption key",
            RamLfePolicyV1 {
                encryption_key: RamLfeEncryptionKeyCommitmentV1::commit(b"other").unwrap(),
                ..base
            },
        ),
        (
            "evaluation key",
            RamLfePolicyV1 {
                evaluation_key: RamLfeEvaluationKeyCommitmentV1::commit(b"other").unwrap(),
                ..base
            },
        ),
        (
            "opening key",
            RamLfePolicyV1 {
                opening_key: RamLfeOpeningKeyCommitmentV1::commit(b"other").unwrap(),
                ..base
            },
        ),
        (
            "PRF key",
            RamLfePolicyV1 {
                prf_key: RamLfePrfKeyCommitmentV1::commit(b"other").unwrap(),
                ..base
            },
        ),
        (
            "relation identity",
            RamLfePolicyV1 {
                relation: RamLfeRelationIdV1::from_descriptor(b"other relation").unwrap(),
                ..base
            },
        ),
    ];
    let mut seen = std::collections::BTreeSet::from([commitment]);
    for (field, substituted) in substitutions {
        assert!(
            seen.insert(substituted.commitment().unwrap()),
            "policy commitment must bind {field}"
        );
    }

    // Unknown plaintext semantics cannot be committed at all.
    let unknown = RamLfePolicyV1 {
        function: RamLfeFunctionIdentityV1 {
            plaintext_semantics: Hash::new(b"other semantics"),
            ..base.function
        },
        ..base
    };
    assert!(unknown.validate().is_err());
    assert!(unknown.commitment().is_err());
}

#[test]
fn function_identity_survives_encryption_key_rotation() {
    let before = policy();
    let after = before.rotate_encryption_keys(
        RamLfeEncryptionKeyCommitmentV1::commit(b"rotated encryption").unwrap(),
        RamLfeEvaluationKeyCommitmentV1::commit(b"rotated evaluation").unwrap(),
        RamLfeOpeningKeyCommitmentV1::commit(b"rotated opening").unwrap(),
    );
    // The policy and all three rotated keys change.
    assert_ne!(after.commitment().unwrap(), before.commitment().unwrap());
    assert_ne!(after.encryption_key, before.encryption_key);
    assert_ne!(after.evaluation_key, before.evaluation_key);
    assert_ne!(after.opening_key, before.opening_key);
    // The logical function with its query limit, its profile, PRF key and
    // relation do not, so the query counts of the identity continue.
    assert_eq!(after.function, before.function);
    assert_eq!(after.function.id().unwrap(), before.function.id().unwrap());
    assert_eq!(after.function.query_limit, limit());
    assert_eq!(after.profile, before.profile);
    assert_eq!(after.prf_key, before.prf_key);
    assert_eq!(after.relation, before.relation);
    // The same key and tape still open the identity under the rotated policy,
    // and the per-execution state lanes and their commitment are the same.
    after
        .function
        .verify_opening(&key(7), &affine_program())
        .unwrap();
    let associated_data = RamLfeAssociatedDataHashV1::commit(b"context").unwrap();
    let lanes = |policy: &RamLfePolicyV1| {
        RamLfeInitialMemoryV1::derive(&key(7), policy.function.id().unwrap(), associated_data)
            .unwrap()
    };
    assert_eq!(lanes(&before), lanes(&after));
    let memory = |policy: &RamLfePolicyV1| {
        RamLfeInitializedMemoryCommitmentV1::commit(
            &key(7),
            policy.function.id().unwrap(),
            associated_data,
            execution(b"execution"),
            &lanes(policy),
        )
        .unwrap()
    };
    assert_eq!(memory(&before), memory(&after));
    // Committing the function again takes no encryption key as input.
    assert_eq!(identity(), before.function);
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::RamLfeMemoryBlindingInputV1",
    frame = "iroha_crypto::ram_lfe::RamLfeMemoryBlindingInputV1"
)]
struct OwnedMemoryBlindingInput {
    function_identity: Hash,
    associated_data_hash: Hash,
    execution_context: Hash,
    program_key: Vec<u8>,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::RamLfeInitializedMemoryInputV1",
    frame = "iroha_crypto::ram_lfe::RamLfeInitializedMemoryInputV1"
)]
struct OwnedInitializedMemoryInput {
    function_identity: Hash,
    associated_data_hash: Hash,
    blinding: Vec<u8>,
    lanes: Vec<u8>,
}

#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::RamLfeOrderedOutputInputV1",
    frame = "iroha_crypto::ram_lfe::RamLfeOrderedOutputInputV1"
)]
struct OwnedOrderedOutputInput {
    blinding: Vec<u8>,
    output_count: u16,
    scalars: Vec<u8>,
}

#[test]
fn memory_and_output_commitments_are_the_documented_framing() {
    let function = identity().id().unwrap();
    let context = RamLfeAssociatedDataHashV1::commit(b"context").unwrap();
    let execution = execution(b"execution");
    let lanes: [u16; 32] = std::array::from_fn(|lane| u16::try_from(lane * 8 + 1).unwrap());
    let memory = RamLfeInitialMemoryV1::from_lanes(&lanes).unwrap();
    let blinding = blake3_commitment(
        "iroha.ram_lfe.v1.memory_blinding",
        &OwnedMemoryBlindingInput {
            function_identity: *function.as_hash(),
            associated_data_hash: *context.as_hash(),
            execution_context: *execution.as_hash(),
            program_key: vec![7; 32],
        },
    );
    assert_eq!(
        RamLfeInitializedMemoryCommitmentV1::commit(&key(7), function, context, execution, &memory)
            .unwrap()
            .as_bytes(),
        &blake3_commitment(
            "iroha.ram_lfe.v1.initialized_memory",
            &OwnedInitializedMemoryInput {
                function_identity: *function.as_hash(),
                associated_data_hash: *context.as_hash(),
                blinding: blinding.to_vec(),
                lanes: lanes.iter().flat_map(|lane| lane.to_le_bytes()).collect(),
            }
        )
    );
    let scalars = [256_u16, 0, 1, 255];
    assert_eq!(
        RamLfeOutputCommitmentV1::commit(
            &RamLfeOrderedOutputV1::from_scalars(&scalars).unwrap(),
            &RamLfeOutputBlindingV1::from_bytes([3; 32]).unwrap(),
        )
        .unwrap()
        .as_bytes(),
        &blake3_commitment(
            "iroha.ram_lfe.v1.ordered_output",
            &OwnedOrderedOutputInput {
                blinding: vec![3; 32],
                output_count: 4,
                scalars: scalars
                    .iter()
                    .flat_map(|scalar| scalar.to_le_bytes())
                    .collect(),
            }
        )
    );
}

#[test]
fn initialized_memory_commitment_binds_key_function_contexts_and_every_lane() {
    let function = identity().id().unwrap();
    let other_function = commit(RamLfeClassV1::Affine, 8, &affine_program())
        .id()
        .unwrap();
    let lanes: [u16; 32] = std::array::from_fn(|lane| u16::try_from(lane * 8).unwrap());
    let memory = RamLfeInitialMemoryV1::from_lanes(&lanes).unwrap();
    let commit = |key_byte: u8,
                  function: RamLfeFunctionIdV1,
                  associated_data: &[u8],
                  seed: &[u8],
                  memory: &RamLfeInitialMemoryV1| {
        RamLfeInitializedMemoryCommitmentV1::commit(
            &key(key_byte),
            function,
            RamLfeAssociatedDataHashV1::commit(associated_data).unwrap(),
            execution(seed),
            memory,
        )
        .unwrap()
    };
    let base = commit(7, function, b"context", b"execution", &memory);
    assert_eq!(base, commit(7, function, b"context", b"execution", &memory));
    let mut seen = std::collections::BTreeSet::from([base]);
    // Identical lanes under two program keys give two commitments.
    assert!(
        seen.insert(commit(8, function, b"context", b"execution", &memory)),
        "the program key must blind the commitment"
    );
    assert!(seen.insert(commit(7, other_function, b"context", b"execution", &memory)));
    assert!(seen.insert(commit(7, function, b"other", b"execution", &memory)));
    assert!(
        seen.insert(commit(7, function, b"context", b"other execution", &memory)),
        "the execution context must blind the commitment"
    );
    for lane in 0..32 {
        let mut changed = lanes;
        changed[lane] = (changed[lane] + 1) % 257;
        let memory = RamLfeInitialMemoryV1::from_lanes(&changed).unwrap();
        assert!(
            seen.insert(commit(7, function, b"context", b"execution", &memory)),
            "lane {lane} must be bound"
        );
    }
}

#[test]
fn initialized_memory_commitment_does_not_confirm_lanes_learned_from_an_opened_output() {
    use crate::ram_lfe::reference::{
        RamLfeReferenceInputV1, ram_lfe_reference_evaluate_v1, ram_lfe_reference_execute_v1,
    };

    // The default identifier program adds lane `i % 32` to input slot `i`.
    let program = crate::default_bfv_programmed_hidden_program();
    let owner_key = key(0x42);
    let function =
        RamLfeFunctionIdentityV1::commit(RamLfeClassV1::Affine, &owner_key, &program, limit())
            .unwrap();
    let input = RamLfeReferenceInputV1::from_bytes(b"+15551234567").unwrap();
    let execution_context = execution(b"network, program and replay nonce");
    let evaluated =
        ram_lfe_reference_evaluate_v1(&function, &owner_key, &program, b"request", &input).unwrap();
    let associated_data = RamLfeAssociatedDataHashV1::commit(b"request").unwrap();
    let published = RamLfeInitializedMemoryCommitmentV1::commit(
        &owner_key,
        function.id().unwrap(),
        associated_data,
        execution_context,
        evaluated.initial_memory(),
    )
    .unwrap();

    // A client knows its input and receives the opened output. Under the
    // hypothesis "slot i gets lane i % 32" it recovers every lane exactly.
    let guessed: Vec<u16> = (0..32)
        .map(|lane| (evaluated.output().scalars()[lane] + 257 - input.slots()[lane]) % 257)
        .collect();
    assert_eq!(guessed, evaluated.initial_memory().lanes());
    let guessed = RamLfeInitialMemoryV1::from_lanes(&guessed).unwrap();
    // Its guess reproduces the function on a fresh input, so it is a real
    // hypothesis about the hidden function.
    let fresh = RamLfeReferenceInputV1::from_bytes(b"+819012345678").unwrap();
    assert_eq!(
        ram_lfe_reference_execute_v1(RamLfeClassV1::Affine, &program, &guessed, &fresh)
            .unwrap()
            .output()
            .scalars(),
        ram_lfe_reference_evaluate_v1(&function, &owner_key, &program, b"request", &fresh)
            .unwrap()
            .output()
            .scalars()
    );

    // Every other input of the commitment is public. Without the program key
    // the client cannot recompute it, so the commitment confirms nothing: no
    // key the client tries gives the published value.
    for attempt in [1_u8, 0x41, 0x43, 0xFF] {
        assert_ne!(
            RamLfeInitializedMemoryCommitmentV1::commit(
                &key(attempt),
                function.id().unwrap(),
                associated_data,
                execution_context,
                &guessed,
            )
            .unwrap(),
            published
        );
    }
    // The owner's key and the same lanes do reproduce it.
    assert_eq!(
        RamLfeInitializedMemoryCommitmentV1::commit(
            &owner_key,
            function.id().unwrap(),
            associated_data,
            execution_context,
            &guessed,
        )
        .unwrap(),
        published
    );

    // A second execution on the same associated data has the same lanes and
    // another commitment, so the commitment does not show that lanes repeat.
    let repeated = RamLfeInitializedMemoryCommitmentV1::commit(
        &owner_key,
        function.id().unwrap(),
        associated_data,
        execution(b"network, program and another replay nonce"),
        evaluated.initial_memory(),
    )
    .unwrap();
    assert_ne!(repeated, published);
}

#[test]
fn output_commitment_binds_blinding_count_order_and_every_scalar() {
    let blinding = RamLfeOutputBlindingV1::from_bytes([3; 32]).unwrap();
    let output = |scalars: &[u16]| RamLfeOrderedOutputV1::from_scalars(scalars).unwrap();
    let base = RamLfeOutputCommitmentV1::commit(&output(&[1, 2, 256]), &blinding).unwrap();
    assert_eq!(
        base,
        RamLfeOutputCommitmentV1::commit(&output(&[1, 2, 256]), &blinding).unwrap()
    );
    let mut seen = std::collections::BTreeSet::from([base]);
    for scalars in [
        &[2, 1, 256][..],
        &[1, 2, 255],
        &[1, 2],
        &[1, 2, 256, 0],
        &[0, 2, 256],
        &[1, 3, 256],
    ] {
        assert!(
            seen.insert(RamLfeOutputCommitmentV1::commit(&output(scalars), &blinding).unwrap())
        );
    }
    // A low-entropy output is hidden by the blinding: another blinding gives
    // another commitment to the same output.
    assert!(
        seen.insert(
            RamLfeOutputCommitmentV1::commit(
                &output(&[1, 2, 256]),
                &RamLfeOutputBlindingV1::from_bytes([4; 32]).unwrap()
            )
            .unwrap()
        )
    );
}

#[test]
fn canonical_commitment_vectors_are_pinned() {
    let identity = identity();
    let policy = policy();
    let context = RamLfeAssociatedDataHashV1::commit(b"context").unwrap();
    let execution = execution(b"execution");
    let memory = RamLfeInitialMemoryV1::from_lanes(&[9; 32]).unwrap();
    let vectors = [
        (
            "function commitment",
            hex::encode(identity.function.as_bytes()),
        ),
        (
            "initializer commitment",
            hex::encode(identity.initializer.as_bytes()),
        ),
        (
            "function identity",
            hex::encode(identity.id().unwrap().as_hash().as_ref()),
        ),
        (
            "policy",
            hex::encode(policy.commitment().unwrap().as_hash().as_ref()),
        ),
        ("associated data", hex::encode(context.as_hash().as_ref())),
        (
            "execution context",
            hex::encode(execution.as_hash().as_ref()),
        ),
        (
            "initialized memory",
            hex::encode(
                RamLfeInitializedMemoryCommitmentV1::commit(
                    &key(7),
                    identity.id().unwrap(),
                    context,
                    execution,
                    &memory,
                )
                .unwrap()
                .as_bytes(),
            ),
        ),
        (
            "ordered output",
            hex::encode(
                RamLfeOutputCommitmentV1::commit(
                    &RamLfeOrderedOutputV1::from_scalars(&[1, 2, 256]).unwrap(),
                    &RamLfeOutputBlindingV1::from_bytes([3; 32]).unwrap(),
                )
                .unwrap()
                .as_bytes(),
            ),
        ),
        (
            "input ciphertext",
            hex::encode(
                RamLfeInputCiphertextCommitmentV1::commit(b"input")
                    .unwrap()
                    .as_hash()
                    .as_ref(),
            ),
        ),
    ];
    let expected = [
        "7288d7be51b502877dea8e24ada39831d7c8214c31b680eb01f990ec4f2d6698",
        "48f906f760329d779c032df1b77ce76ddd8d706801ba55976725eacc13c27d23",
        "9bd080be150e1323b545166c91e8c3856390175691ebcd953722d8b0f58ceb75",
        "411743239f4e94ce772d04de59f73f3f32e8f9f79b92f9d39eb6330c5311268f",
        "a5b3b5f0acd93d3b1bc0bc6ee5a93ec1a01d7887af0e2789ac98fcef52178e25",
        "de1512e2f9e48c6333e318f666596a1d9b3f69b88409c5238786ba007e9813ef",
        "16b034156daf37aea2e7db19a90aae245e0d5578c31482e07196522d5fecca08",
        "32134cf228b6bf19be6fe6855a3d543962d4e7a01e847e89850aa322a1e4b63e",
        "807c20e42998b60eba8bf6f107e1c640c4875057b5b7f27af298746b73e50837",
    ];
    let actual: Vec<(&str, &str)> = vectors
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let expected: Vec<(&str, &str)> = vectors
        .iter()
        .map(|(name, _)| *name)
        .zip(expected)
        .collect();
    assert_eq!(actual, expected);
}
