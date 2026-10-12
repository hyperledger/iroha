//! Canonical frame, identity and mutation tests for semantic profiles.
//!
//! The expected frames and digests were written out by hand and hashed with an
//! independent SHA3-256 (`scripts/zk_semantic_profile_reference.py` reproduces
//! them); no encoder of this crate derives them.

use super::*;

type Parameter<'a> = (&'a str, SemanticProfileValueV1<'a>);

const ARITIES: [u64; 5] = [16, 16, 8, 8, 4];

fn example() -> Vec<Parameter<'static>> {
    vec![
        ("queries", SemanticProfileValueV1::U64(77)),
        ("hash", SemanticProfileValueV1::Text("FIPS202:SHA3-256")),
        ("domain", SemanticProfileValueV1::Bytes(b"\x00\xffdomain")),
        ("arities", SemanticProfileValueV1::U64List(&ARITIES)),
    ]
}

fn profile(parameters: &[Parameter<'_>]) -> SemanticProfileV1 {
    SemanticProfileV1::new(
        SemanticProfileKindV1::Transcript,
        "example.profile-v1",
        parameters,
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}

#[test]
fn canonical_frame_and_identity_match_independent_vectors() {
    let profile = profile(&example());
    assert_eq!(profile.kind(), SemanticProfileKindV1::Transcript);
    assert_eq!(profile.name(), "example.profile-v1");
    assert_eq!(profile.as_bytes().len(), 194);
    assert_eq!(
        hex(profile.as_bytes()),
        concat!(
            "69726f68613a73656d616e7469632d70726f66696c653a763100",
            "0a0000007472616e736372697074",
            "120000006578616d706c652e70726f66696c652d7631",
            "04000000",
            "0700000071756572696573014d00000000000000",
            "04000000686173680210000000464950533230323a534841332d323536",
            "06000000646f6d61696e030800000000ff646f6d61696e",
            "07000000617269746965730405000000",
            "1000000000000000100000000000000008000000000000000800000000000000",
            "0400000000000000",
        )
    );
    assert_eq!(
        profile.id().to_string(),
        "557ef3c818f356160526fba916c44b09ab2775b824b57c79c5fe8187ae7e2349"
    );
    assert_eq!(
        format!("{:?}", profile.id()),
        "SemanticProfileIdV1(557ef3c818f356160526fba916c44b09ab2775b824b57c79c5fe8187ae7e2349)"
    );
    assert_eq!(
        SemanticProfileIdV1::from_bytes(*profile.id().as_bytes()),
        profile.id()
    );

    let empty = SemanticProfileV1::new(SemanticProfileKindV1::KeyDerivation, "x", &[]).unwrap();
    assert_eq!(
        hex(empty.as_bytes()),
        "69726f68613a73656d616e7469632d70726f66696c653a7631000e0000006b65792d64657269766174696f6e010000007800000000"
    );
    assert_eq!(
        empty.id().to_string(),
        "3d7890a841af88bace65d95a3a7edcdbb8091b2ce94c9ecd9325fc67ea7b8467"
    );
}

#[test]
fn every_changed_reordered_or_omitted_element_changes_the_identity() {
    let baseline = profile(&example());
    let mut seen = vec![baseline.id()];
    let mut distinct = |changed: SemanticProfileV1| {
        assert!(
            !seen.contains(&changed.id()),
            "two different profiles share one identity"
        );
        assert_ne!(changed.as_bytes(), baseline.as_bytes());
        seen.push(changed.id());
    };

    // Kind and name.
    for kind in SemanticProfileKindV1::ALL {
        if kind != SemanticProfileKindV1::Transcript {
            distinct(SemanticProfileV1::new(kind, "example.profile-v1", &example()).unwrap());
        }
    }
    distinct(
        SemanticProfileV1::new(
            SemanticProfileKindV1::Transcript,
            "example.profile-v2",
            &example(),
        )
        .unwrap(),
    );

    // Each value, each key and each type.
    let other_arities = [16_u64, 16, 8, 8, 2];
    let longer_arities = [16_u64, 16, 8, 8, 4, 1];
    for (index, replacement) in [
        (0, ("queries", SemanticProfileValueV1::U64(78))),
        (0, ("query", SemanticProfileValueV1::U64(77))),
        (0, ("queries", SemanticProfileValueV1::U64List(&[77]))),
        (
            1,
            ("hash", SemanticProfileValueV1::Text("FIPS202:SHA3-384")),
        ),
        (
            1,
            ("hash", SemanticProfileValueV1::Bytes(b"FIPS202:SHA3-256")),
        ),
        (
            2,
            ("domain", SemanticProfileValueV1::Bytes(b"\x00\xffdomaim")),
        ),
        (2, ("domain", SemanticProfileValueV1::Bytes(b""))),
        (
            3,
            ("arities", SemanticProfileValueV1::U64List(&other_arities)),
        ),
        (
            3,
            ("arities", SemanticProfileValueV1::U64List(&longer_arities)),
        ),
        (3, ("arities", SemanticProfileValueV1::U64List(&[]))),
    ] {
        let mut changed = example();
        changed[index] = replacement;
        distinct(profile(&changed));
    }

    // Every adjacent swap, every omission and one added parameter.
    for first in 0..example().len() - 1 {
        let mut reordered = example();
        reordered.swap(first, first + 1);
        distinct(profile(&reordered));
    }
    for omitted in 0..example().len() {
        let mut shorter = example();
        shorter.remove(omitted);
        distinct(profile(&shorter));
    }
    let mut longer = example();
    longer.push(("grinding_bits", SemanticProfileValueV1::U64(0)));
    distinct(profile(&longer));

    // A boundary moved between two neighbouring values is a different frame.
    distinct(profile(&[
        ("a", SemanticProfileValueV1::Text("bc")),
        ("d", SemanticProfileValueV1::Text("")),
    ]));
    distinct(profile(&[
        ("a", SemanticProfileValueV1::Text("b")),
        ("d", SemanticProfileValueV1::Text("c")),
    ]));
}

#[test]
fn identity_is_a_function_of_the_declared_parameters_only() {
    // Equal parameters built from separate allocations have one identity.
    let arities = ARITIES.to_vec();
    let text = String::from("FIPS202:SHA3-256");
    let rebuilt = profile(&[
        ("queries", SemanticProfileValueV1::U64(77)),
        ("hash", SemanticProfileValueV1::Text(&text)),
        (
            "domain",
            SemanticProfileValueV1::Bytes(&[0, 0xff, b'd', b'o', b'm', b'a', b'i', b'n']),
        ),
        ("arities", SemanticProfileValueV1::U64List(&arities)),
    ]);
    assert_eq!(rebuilt, profile(&example()));
    assert_eq!(rebuilt.id(), profile(&example()).id());
}

#[test]
fn labels_keys_counts_and_value_lengths_are_bounded() {
    let new = |name: &str, parameters: &[Parameter<'_>]| {
        SemanticProfileV1::new(SemanticProfileKindV1::NativeCommitment, name, parameters)
    };
    for name in [
        "",
        "Upper",
        "space name",
        ".leading",
        "trailing.",
        "double..dot",
        "tab\tname",
        "caf\u{e9}",
    ] {
        assert_eq!(
            new(name, &[]),
            Err(SemanticProfileErrorV1::Label),
            "{name:?}"
        );
        assert_eq!(
            new("ok", &[(name, SemanticProfileValueV1::U64(0))]),
            Err(SemanticProfileErrorV1::Label),
            "{name:?}"
        );
    }
    let longest = "a".repeat(SEMANTIC_PROFILE_MAX_LABEL_BYTES_V1);
    assert!(new(&longest, &[]).is_ok());
    assert_eq!(
        new(&format!("{longest}a"), &[]),
        Err(SemanticProfileErrorV1::Label)
    );
    assert!(
        new(
            "a.b-c_d0",
            &[("k0.k1-k2_k3", SemanticProfileValueV1::U64(1))]
        )
        .is_ok()
    );

    assert_eq!(
        new(
            "ok",
            &[
                ("same", SemanticProfileValueV1::U64(1)),
                ("other", SemanticProfileValueV1::U64(2)),
                ("same", SemanticProfileValueV1::U64(3)),
            ]
        ),
        Err(SemanticProfileErrorV1::DuplicateKey)
    );

    let keys: Vec<String> = (0..=SEMANTIC_PROFILE_MAX_PARAMETERS_V1)
        .map(|index| format!("k{index}"))
        .collect();
    let parameters: Vec<Parameter<'_>> = keys
        .iter()
        .map(|key| (key.as_str(), SemanticProfileValueV1::U64(0)))
        .collect();
    assert!(new("ok", &parameters[..SEMANTIC_PROFILE_MAX_PARAMETERS_V1]).is_ok());
    assert_eq!(
        new("ok", &parameters),
        Err(SemanticProfileErrorV1::TooManyParameters)
    );

    let bytes = vec![0_u8; SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 + 1];
    let text = "t".repeat(SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 + 1);
    let list = vec![0_u64; SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 / 8 + 1];
    assert!(
        new(
            "ok",
            &[(
                "v",
                SemanticProfileValueV1::Bytes(&bytes[..SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1])
            )]
        )
        .is_ok()
    );
    assert!(
        new(
            "ok",
            &[(
                "v",
                SemanticProfileValueV1::U64List(&list[..SEMANTIC_PROFILE_MAX_VALUE_BYTES_V1 / 8])
            )]
        )
        .is_ok()
    );
    for value in [
        SemanticProfileValueV1::Bytes(&bytes),
        SemanticProfileValueV1::Text(&text),
        SemanticProfileValueV1::U64List(&list),
    ] {
        assert_eq!(
            new("ok", &[("v", value)]),
            Err(SemanticProfileErrorV1::ValueTooLong)
        );
    }
    for error in [
        SemanticProfileErrorV1::Label,
        SemanticProfileErrorV1::DuplicateKey,
        SemanticProfileErrorV1::TooManyParameters,
        SemanticProfileErrorV1::ValueTooLong,
        SemanticProfileErrorV1::Noncanonical,
    ] {
        assert!(error.to_string().starts_with("semantic profile"));
    }
}

#[test]
fn kind_labels_are_distinct_and_inside_the_label_grammar() {
    let labels: Vec<_> = SemanticProfileKindV1::ALL
        .iter()
        .map(|kind| kind.label())
        .collect();
    assert_eq!(
        labels,
        [
            "transcript",
            "native-commitment",
            "in-circuit-digest",
            "standard-primitive",
            "key-derivation",
            "lattice-trapdoor"
        ]
    );
    for label in labels {
        assert!(is_label(label));
    }
}

#[test]
fn decoding_returns_the_ordered_parameters_and_refuses_every_noncanonical_frame() {
    let original = profile(&example());
    let (decoded, parameters) = SemanticProfileV1::decode(original.as_bytes()).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(parameters, original.parameters());
    let expected: Vec<_> = example()
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.to_owned_value()))
        .collect();
    assert_eq!(parameters, expected);
    for (key, value) in &parameters {
        assert!(example().contains(&(key.as_str(), value.as_value())));
    }

    let frame = original.as_bytes();
    let refuse = |bytes: &[u8], what: &str| {
        assert_eq!(
            SemanticProfileV1::decode(bytes),
            Err(SemanticProfileErrorV1::Noncanonical),
            "{what}"
        );
    };
    // Every strict prefix and one trailing byte.
    for length in 0..frame.len() {
        refuse(&frame[..length], "truncated frame");
    }
    let mut longer = frame.to_vec();
    longer.push(0);
    refuse(&longer, "trailing byte");
    // Magic, kind label, name, key, type byte and count.
    let at = |needle: &[u8]| {
        frame
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap()
    };
    let mutate = |offset: usize, byte: u8, what: &str| {
        let mut changed = frame.to_vec();
        changed[offset] = byte;
        refuse(&changed, what);
    };
    mutate(0, b'I', "magic");
    mutate(25, 1, "magic terminator");
    mutate(at(b"transcript"), b'T', "unknown kind");
    mutate(at(b"example"), b'E', "name outside the grammar");
    mutate(at(b"queries"), b'Q', "key outside the grammar");
    mutate(at(b"queries") + 7, 9, "unknown type byte");
    mutate(at(b"queries") + 7, 0, "zero type byte");
    mutate(at(b"FIPS202"), 0xff, "text that is not UTF-8");
    let count = at(b"example.profile-v1") + 18;
    assert_eq!(&frame[count..count + 4], &[4, 0, 0, 0]);
    mutate(count, 3, "fewer parameters than encoded");
    mutate(count, 5, "more parameters than encoded");
    // A repeated key and lengths beyond the ceilings.
    let mut repeated = frame.to_vec();
    let hash = at(b"hash");
    repeated[hash - 4..hash + 4].copy_from_slice(&frame[at(b"queries") - 4..at(b"queries") + 4]);
    refuse(&repeated, "frame that could repeat or corrupt a key");
    let mut oversized = SEMANTIC_PROFILE_MAGIC_V1.to_vec();
    oversized.extend_from_slice(&10_u32.to_le_bytes());
    oversized.extend_from_slice(b"transcript");
    oversized.extend_from_slice(&u32::MAX.to_le_bytes());
    refuse(&oversized, "name length beyond the frame");
    let mut many = SEMANTIC_PROFILE_MAGIC_V1.to_vec();
    many.extend_from_slice(&10_u32.to_le_bytes());
    many.extend_from_slice(b"transcript");
    many.extend_from_slice(&1_u32.to_le_bytes());
    many.push(b'x');
    many.extend_from_slice(&256_u32.to_le_bytes());
    refuse(&many, "parameter count beyond the ceiling");
    let mut duplicate = SEMANTIC_PROFILE_MAGIC_V1.to_vec();
    duplicate.extend_from_slice(&10_u32.to_le_bytes());
    duplicate.extend_from_slice(b"transcript");
    duplicate.extend_from_slice(&1_u32.to_le_bytes());
    duplicate.push(b'x');
    duplicate.extend_from_slice(&2_u32.to_le_bytes());
    for _ in 0..2 {
        duplicate.extend_from_slice(&1_u32.to_le_bytes());
        duplicate.push(b'k');
        duplicate.push(1);
        duplicate.extend_from_slice(&7_u64.to_le_bytes());
    }
    refuse(&duplicate, "repeated key");
    let mut list = SEMANTIC_PROFILE_MAGIC_V1.to_vec();
    list.extend_from_slice(&10_u32.to_le_bytes());
    list.extend_from_slice(b"transcript");
    list.extend_from_slice(&1_u32.to_le_bytes());
    list.push(b'x');
    list.extend_from_slice(&1_u32.to_le_bytes());
    list.extend_from_slice(&1_u32.to_le_bytes());
    list.push(b'k');
    list.push(4);
    list.extend_from_slice(&u32::MAX.to_le_bytes());
    refuse(&list, "list count beyond the ceiling");
}

#[test]
fn profile_set_identity_binds_every_member_and_their_order() {
    // Independent vectors: SHA3-256 of the magic, the count and the identities.
    let first = profile(&example()).id();
    let second = SemanticProfileV1::new(SemanticProfileKindV1::KeyDerivation, "x", &[])
        .unwrap()
        .id();
    assert_eq!(
        semantic_profile_set_id_v1(&[first, second]).to_string(),
        "d5573da9c87a804d51f301b1dd7111ee9747aafffb3017ad86dfc2f49d4ceba9"
    );
    assert_eq!(
        semantic_profile_set_id_v1(&[second, first]).to_string(),
        "2e3fcc0b0e50ef42a224f72aaff105378a549fd8ecdec2c1289a5d1bb187363a"
    );
    assert_eq!(
        semantic_profile_set_id_v1(&[first]).to_string(),
        "cff840e39aaf7c56fe097d5c7ac3a687cc2d4debf4873fa986e83da109d41cc3"
    );
    assert_eq!(
        semantic_profile_set_id_v1(&[]).to_string(),
        "0c4e4fcc83e929fbdd4d60e2fe247e53f2eebe5ec755d732bc22f10813afed5b"
    );
    assert_ne!(semantic_profile_set_id_v1(&[first]), first);
    assert_ne!(
        semantic_profile_set_id_v1(&[first, first]),
        semantic_profile_set_id_v1(&[first])
    );
}
