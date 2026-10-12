//! CRT conformance: every entry of the official `crt_vole_commit_tvs` vectors (the
//! CRT lift `W_CRT * Delta'` of the concatenated small-VOLE challenges), and the
//! provenance of the embedded table sets: each is regenerated and compared with the
//! embedded statics word for word, with the generated source on disk, and with the
//! pinned SHAKE256 digests of the reviewed prototype tables.
//!
//! `M_TREE` and the tree moduli are pinned by the official `field_tvs` vectors in
//! `tests/conformance_field.rs`.
//!
//! To rewrite `src/crt/generated/*.rs` from the generator run
//! `cargo test -p iroha_zkp_vole --test conformance_crt -- --ignored`.

mod common;

use std::{fmt::Write as _, fs, path::PathBuf};

use common::Fixture;
use iroha_zkp_vole::{
    crt::{
        CrtTables, Profile,
        codec::{decode_words, encode_words, write_rust_source},
        generated::{file_name, tables},
        generator::{generate, generate_profile},
        matrix::BitMatrix,
        tables_for,
    },
    params::FAEST_PARAMETER_SETS,
};

/// SHAKE256, squeezed to 32 bytes, of the canonical image of each table of each
/// profile: the rows in order, every row as `ceil(width / 64)` little-endian `u64`
/// words. One line per profile in the order of [`Profile::ALL`], with the tables in
/// the order `F`, `G`, `W_TREE`, `W_GATE`, `W_CRT`.
///
/// The values are those of `tables/SHAKE256SUMS.txt` of the reviewed prototype, an
/// independent Python port of the FAEST v3.0.2 reference table generator.
const DIGESTS: [[&str; 5]; 8] = [
    [
        "798fe9b6448cb3b373e5808b145df42b68e8027b802aab52215785e9764fac9c",
        "62630e2cb1a35dfa83fe73d3d69f4c3597697f8ed50d54631ec48630f4fcc74f",
        "eaf3e8b14060a62d47d54d7004ca43fcbbe4a7ce3318890bf195de9d43a02a0c",
        "7c7f0504e0611fb687ac8cd2e87f19886af7b3390cf9aff5339fa12c52e20a60",
        "762dc303d4b0289eaa9be65b301a67ce9be2b5f36d03000e7561b14ffc09ff62",
    ],
    [
        "a58c299f362ac24e137edfca92eea7a14a3f39c308537a0bd8d2784f57ea45bb",
        "1b446540773b29fe55ce83ff3be1409f0fd5a9304ed5aa8f33c8a543dd8d1228",
        "19736dc0fa527af67b6f09e53bb45f0ce41bbe4f2d6a9155249ab506c5ee95da",
        "ee80690ef437374001bde9ebef8c2ab9c910cc3fdd227f88b9b43796e2490d73",
        "4a9273ea6a8bf7169dc466ef68861a7e0cb48c26c5a5fdb1cbcd61e2be2629fb",
    ],
    [
        "b0a114abfc7fecf547153a1ec373973f41fc896e284462efd2332877e14b5175",
        "07593471aa6634ae1743dac7a9c4c52e3bd43cbc99704df0248f8ba860efabd5",
        "e9b95ddd41ae264f8506eac513cf875b3a82015594e443a685805c41069160b4",
        "6ca9ac87fda702826ae47e770423c754842c5aee9d7a10713164af13f73d01bd",
        "2fc5d76d15a13206045e435027204efa6f5b659e08fa280bc7a55414b29f0591",
    ],
    [
        "d17f255c9cb63cbb8afdc9873df4ef0a7dd3e4e2b64a8cbb107ffb22e818d755",
        "0db822688b3345db824a279b3a435d22562cf437d33d4c6f325dc77c9cd18faf",
        "5013cedf9bb9d14bc41b5eafd2f38ab7ebe531d661aeee92e8069da62adbcb80",
        "8870d4cd78e573a533af616ccaec0e5295e97639ce84cf589688eac32882edfc",
        "c85c7d15637d52ee9e60729fee014de9ad5835737fd82fbb463418f22389f590",
    ],
    [
        "84bd356d35b32cbdd5f86a189e2cc8c7abfe64435a45e9201f9478b0aa7598aa",
        "a992357dc6a85a67c0a399a022010bdc3c120b3dc59f1784846bccf970c1eaa4",
        "8ff164cb2d215314a807d8e4b1843c4da81118a43c4db24fd85c965ff8b143d8",
        "b91b2e8672d4080d93dccee4cc1efbdb06ab25b95f18fc2491f727b9d4c0efad",
        "cb61b288eff5d1d4da4b346b5a517c2861b5a6d1a239de6cffa3d3cce779e7d5",
    ],
    [
        "0ab5aa45765fdb55eb30d14608b982e655a46edd1049b8a3ede8000c16925502",
        "818965e941a7d5be418db835a9ad7486d6475174d704e429664b5315e372b740",
        "f08e281e42c0bca1feafbbadfe82d796029be70c30b405461b9fece1e5475622",
        "ca1c0ee3e4ac33fcf60eb953374a1c0415d9f61436b841c0e618d04f5b55e56b",
        "298b46c0565f46393530c9b2d0dfd4af0aeb71825f7a11c3c336aca48ad10318",
    ],
    [
        "b0a114abfc7fecf547153a1ec373973f41fc896e284462efd2332877e14b5175",
        "ce1e3b6fd3da8b069194eb6e41daabe3ea82ad52f6498377fbead7cbe72939a4",
        "786dd563c6a3b7df9b8dcc6ad185db76f9d67714173e0afe70fda00b00536439",
        "10694ddec80e0053fb920f2b2456ed59f9c18cbf1b8688f9cccfa7fae442328c",
        "64d2c292f3b0ccdd68b086a3fc58aa03b5cf044b5cac9ef32f67fad903ac475c",
    ],
    [
        "8c9f5dbcf69bd2213fc5135f1d2ec01bb594aaa62ad5b0c27d9d051622e8b83b",
        "98ed94c6eddecd8675ceb674eee5124d669316fcfe73dcffdcf5ff74d262b496",
        "e4b68e342c38c0e5c4f5de4c66767e3683c9af65cfdf2e6aa6af59eafe0bf90f",
        "fc35931ff840d2d9d8160abaf5db9936ae8b99d58469bdb8a1373a0b817c83e6",
        "7fe81ecdf70022af4f5b14d65d6261ac6d8537a4e219791a9c8c7e5368d47519",
    ],
];

/// SHAKE256, squeezed to 32 bytes, of the canonical image of a matrix, as lowercase
/// hexadecimal.
fn digest(matrix: &BitMatrix<'_>) -> String {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut sponge = sha3::Shake256::default();
    for word in matrix.as_words() {
        sponge.update(&word.to_le_bytes());
    }
    let mut out = [0u8; 32];
    sponge.finalize_xof().read(&mut out);
    let mut hex = String::new();
    for byte in out {
        write!(hex, "{byte:02x}").expect("writing to a string");
    }
    hex
}

/// The five tables of a set in the order of [`DIGESTS`], with their names.
fn matrices<'t, 'a>(tables: &'t CrtTables<'a>) -> [(&'static str, &'t BitMatrix<'a>); 5] {
    [
        ("F", tables.f()),
        ("G", tables.g()),
        ("W_TREE", tables.w_tree()),
        ("W_GATE", tables.w_gate()),
        ("W_CRT", tables.w_crt()),
    ]
}

/// Directory of the generated sources.
fn generated_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/crt/generated")
}

#[test]
fn every_crt_vole_commit_vector_is_reproduced() {
    let fixture = Fixture::load("crt_vole_commit_tvs");
    assert_eq!(fixture.names().len(), 2 * Profile::ALL.len());
    for profile in Profile::ALL {
        let tables = tables(profile);
        let name = profile.name();
        let lambda_bytes = usize::try_from(tables.lambda()).expect("small") / 8;
        let n_delta = usize::try_from(tables.n_delta()).expect("small");

        // expected_crt_delta_bytes = W_CRT * delta_bytes, as a field element.
        let delta = fixture.bytes(&format!("crt_tvs_{name}.delta_bytes"));
        let expected = fixture.bytes(&format!("crt_tvs_{name}.expected_crt_delta_bytes"));
        assert_eq!(delta.len(), n_delta.div_ceil(8), "{name}");
        assert_eq!(expected.len(), lambda_bytes, "{name}");
        let mut out = vec![0xaau8; expected.len()];
        tables
            .w_crt()
            .mul_vec_bytes(&mut out, &delta)
            .expect("ceil(n_delta / 8) input bytes and lambda / 8 output bytes");
        assert_eq!(out, expected, "{name}");

        // The same product on words.
        let mut delta_words = vec![0u64; tables.w_crt().words_per_row()];
        for (position, byte) in delta.iter().enumerate() {
            delta_words[position / 8] |= u64::from(*byte) << (8 * (position % 8));
        }
        let mut out_words = vec![u64::MAX; lambda_bytes / 8];
        tables
            .w_crt()
            .mul_vec(&mut out_words, &delta_words)
            .expect("word lengths");
        let as_bytes: Vec<u8> = out_words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(as_bytes, expected, "{name}");

        // And bit by bit: output bit `r` is the inner product of row `r` with Delta.
        for (row, byte) in expected.iter().enumerate().flat_map(|(position, byte)| {
            (0..8).map(move |bit| (8 * position + bit, (byte >> bit) & 1 == 1))
        }) {
            assert_eq!(
                tables.w_crt().row_dot(row, &delta_words),
                Ok(byte),
                "{name}"
            );
        }
    }
    fixture.assert_consumed("");
}

#[test]
fn the_vectors_are_reproduced_through_every_standard_row() {
    // The fixture has eight sets; the twelve rows reach them through their tables.
    let fixture = Fixture::load("crt_vole_commit_tvs");
    for set in FAEST_PARAMETER_SETS {
        let tables = tables_for(set.vole()).expect("standard row");
        let name = tables.profile().expect("standard tables").name();
        let delta = fixture.bytes(&format!("crt_tvs_{name}.delta_bytes"));
        let expected = fixture.bytes(&format!("crt_tvs_{name}.expected_crt_delta_bytes"));
        assert_eq!(delta.len(), set.vole().n_delta().div_ceil(8));
        let mut out = vec![0u8; set.vole().lambda().bytes()];
        tables
            .w_crt()
            .mul_vec_bytes(&mut out, &delta)
            .expect("lengths of the row");
        assert_eq!(out, expected, "{}", set.name());
    }
    fixture.assert_consumed("");
}

#[test]
fn regenerated_tables_equal_the_embedded_ones_and_the_pinned_digests() {
    for (profile, pinned) in Profile::ALL.into_iter().zip(DIGESTS) {
        let name = profile.name();
        let embedded = tables(profile);
        let (lambda, tau, w_grind) = profile.parameters();
        let generated = generate(lambda, tau, w_grind).expect("standard profile");
        assert_eq!(generate_profile(profile).as_ref(), Ok(&generated), "{name}");

        // Word for word, part by part.
        let (left, right) = (generated.as_words(), embedded.as_words());
        assert_eq!(
            (left.lambda, left.tau, left.w_grind, left.n_mult),
            (right.lambda, right.tau, right.w_grind, right.n_mult),
            "{name}"
        );
        assert_eq!(left.tree_moduli, right.tree_moduli, "{name} TREE_MODULI");
        assert_eq!(left.m_tree, right.m_tree, "{name} M_TREE");
        assert!(left.f == right.f, "{name} F differs");
        assert!(left.g == right.g, "{name} G differs");
        assert!(left.w_tree == right.w_tree, "{name} W_TREE differs");
        assert!(left.w_gate == right.w_gate, "{name} W_GATE differs");
        assert!(left.w_crt == right.w_crt, "{name} W_CRT differs");
        assert!(&generated == embedded, "{name} differs");
        assert!(
            encode_words(&generated) == encode_words(embedded),
            "{name} canonical words differ"
        );

        // The digests of the reviewed prototype, for both.
        for ((table, matrix), expected) in matrices(embedded).into_iter().zip(pinned) {
            assert_eq!(digest(matrix), expected, "{name} {table} embedded");
        }
        for ((table, matrix), expected) in matrices(&generated).into_iter().zip(pinned) {
            assert_eq!(digest(matrix), expected, "{name} {table} generated");
        }
    }
}

#[test]
fn generated_sources_on_disk_are_what_the_writer_renders() {
    for profile in Profile::ALL {
        let path = generated_dir().join(file_name(profile));
        let on_disk = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let rendered = write_rust_source(tables(profile), profile.name()).expect("valid label");
        assert!(
            rendered == on_disk,
            "{} is not the rendering of its tables",
            path.display()
        );
        assert!(
            on_disk.starts_with("// @generated by "),
            "{}",
            path.display()
        );
        // Fixed layout: four `u64` or eight `u16` literals per line at most.
        for line in on_disk.lines().filter(|line| line.starts_with("    0x")) {
            let literals = line.matches("0x").count();
            let limit = if line.contains('_') { 4 } else { 8 };
            assert!(literals <= limit, "{line}");
        }
    }
    // The upstream licence of the construction is kept beside the tables.
    let licence = fs::read_to_string(generated_dir().join("LICENSE.faest-ref")).expect("licence");
    let fixture_licence = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/faest_v3_0_2/LICENSE.faest-ref"),
    )
    .expect("fixture licence");
    assert_eq!(licence, fixture_licence);
    assert!(licence.contains("Permission is hereby granted, free of charge"));
}

/// Rewrites `src/crt/generated/*.rs` from the generator. Run explicitly with
/// `-- --ignored`; the build then embeds the new files, and the other tests of this
/// file decide whether they are the expected tables.
#[test]
#[ignore = "rewrites the generated sources in the source tree"]
fn rewrite_the_generated_sources() {
    let directory = generated_dir();
    for profile in Profile::ALL {
        let generated = generate_profile(profile).expect("standard profile");
        let source = write_rust_source(&generated, profile.name()).expect("valid label");
        // Deterministic: a second rendering is identical.
        assert_eq!(
            write_rust_source(&generated, profile.name()).as_ref(),
            Ok(&source)
        );
        let path = directory.join(file_name(profile));
        if fs::read_to_string(&path).ok().as_ref() != Some(&source) {
            fs::write(&path, &source).expect("write the generated source");
        }
        assert!(fs::read_to_string(&path).expect("read back") == source);
    }
}

#[test]
fn gate_counts_challenge_lengths_and_first_moduli() {
    let expected = [
        (312, 121, 0x805),
        (312, 120, 0x11b),
        (504, 180, 0x1009),
        (504, 184, 0x11b),
        (696, 250, 0x1009),
        (704, 248, 0x11b),
        (504, 184, 0x1009),
        (504, 184, 0x11b),
    ];
    for (profile, (n_mult, n_delta, first)) in Profile::ALL.into_iter().zip(expected) {
        let tables = tables(profile);
        let name = profile.name();
        assert_eq!(tables.n_mult(), n_mult, "{name}");
        assert_eq!(profile.n_mult(), n_mult, "{name}");
        assert_eq!(tables.n_delta(), n_delta, "{name}");
        assert_eq!(tables.profile(), Some(profile));
        assert_eq!(tables.tree_modulus(0), Some(first), "{name}");
        assert_eq!(tables.residue_offset(0), Some(0), "{name}");
    }
}

#[test]
fn canonical_words_round_trip_for_every_profile() {
    for profile in Profile::ALL {
        let tables = tables(profile);
        let words = encode_words(tables);
        assert!(
            decode_words(&words).as_ref() == Ok(tables),
            "{}",
            profile.name()
        );
        assert!(decode_words(&words[..words.len() - 1]).is_err());
        let mut flipped = words.clone();
        // The last word is the last row of `W_CRT`, which is zero.
        let position = words.len() - 1;
        flipped[position] ^= 1 << 63;
        assert!(decode_words(&flipped).is_err(), "{}", profile.name());
    }
}
