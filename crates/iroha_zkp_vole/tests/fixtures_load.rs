//! Loads every converted FAEST v3.0.2 reference-vector fixture and checks known shapes.

mod common;

use common::{FIXTURE_FILES, Fixture};

const AES_SETS: [(&str, usize); 6] = [
    ("FAEST_128S", 16),
    ("FAEST_128F", 16),
    ("FAEST_192S", 24),
    ("FAEST_192F", 24),
    ("FAEST_256S", 32),
    ("FAEST_256F", 32),
];
const EM_SETS: [(&str, usize); 6] = [
    ("FAEST_EM_128S", 16),
    ("FAEST_EM_128F", 16),
    ("FAEST_EM_192S", 24),
    ("FAEST_EM_192F", 24),
    ("FAEST_EM_256S", 32),
    ("FAEST_EM_256F", 32),
];

#[test]
fn every_fixture_file_loads_with_the_expected_entry_count() {
    let expected = [138, 16, 50, 60, 18, 12, 27, 120];
    for (file, count) in FIXTURE_FILES.iter().zip(expected) {
        let fixture = Fixture::load(file);
        assert_eq!(fixture.names().len(), count, "{file}");
    }
}

#[test]
fn prg_vectors_have_the_expected_lengths() {
    let fixture = Fixture::load("prg_tvs");
    assert_eq!(fixture.names()[0], "prg_tvs.key_128");
    for lambda in [128_usize, 192, 256] {
        assert_eq!(
            fixture.bytes(&format!("prg_tvs.key_{lambda}")).len(),
            lambda / 8
        );
        assert_eq!(fixture.bytes(&format!("prg_tvs.iv_{lambda}")).len(), 16);
        assert_eq!(
            fixture.bytes(&format!("prg_tvs.expected_{lambda}")).len(),
            14 * 16 + 8
        );
        assert!(u32::try_from(fixture.integer(&format!("prg_tvs.tweak_{lambda}"))).is_ok());
    }
    assert_eq!(
        fixture.bytes("prg_tvs.key_128"),
        [
            0xe1, 0x52, 0x3a, 0x89, 0x80, 0xc1, 0x62, 0x83, 0xcb, 0xc8, 0x5e, 0x71, 0x70, 0x3a,
            0x04, 0xd1
        ]
    );
    assert_eq!(fixture.integer("prg_tvs.tweak_128"), 1_180_718_807);
}

#[test]
fn component_vectors_have_the_expected_lengths() {
    let bavc = Fixture::load("bavc_tvs");
    let vole = Fixture::load("vole_tvs");
    let field = Fixture::load("field_tvs");
    for (set, is_em, lambda_bytes) in AES_SETS
        .iter()
        .map(|(set, bytes)| (*set, false, *bytes))
        .chain(EM_SETS.iter().map(|(set, bytes)| (*set, true, *bytes)))
    {
        let name = |field: &str| format!("bavc_tvs.{set}.{field}");
        assert_eq!(bavc.bytes(&name("h")).len(), 2 * lambda_bytes);
        for hashed in ["hashed_k", "hashed_sd", "hashed_decom_i", "hashed_rec_sd"] {
            assert_eq!(bavc.bytes(&name(hashed)).len(), 64);
        }
        assert!(!bavc.u16_list(&name("i_delta")).is_empty());
        assert_eq!(bavc.bytes(&name("leaf_commit_key")).len(), lambda_bytes);
        assert_eq!(bavc.bytes(&name("leaf_commit_iv")).len(), 16);
        assert!(u32::try_from(bavc.integer(&name("tweak"))).is_ok());
        assert_eq!(
            bavc.bytes(&name("leaf_commit_expected_sd")).len(),
            lambda_bytes
        );
        let com_factor = if is_em { 2 } else { 3 };
        assert_eq!(
            bavc.bytes(&name("leaf_commit_expected_com")).len(),
            com_factor * lambda_bytes
        );
        assert_eq!(
            bavc.names().contains(&name("leaf_commit_uhash")),
            !is_em,
            "{set}"
        );

        let name = |field: &str| format!("vole_tvs.{set}.{field}");
        assert_eq!(vole.bytes(&name("h")).len(), 2 * lambda_bytes);
        assert_eq!(vole.bytes(&name("chall")).len(), lambda_bytes);
        for hashed in [
            "hashed_c",
            "hashed_u",
            "hashed_c_mult",
            "hashed_v",
            "hashed_barU",
            "hashed_barV",
            "hashed_q",
            "hashed_barQ",
        ] {
            assert_eq!(vole.bytes(&name(hashed)).len(), 64);
        }

        let name = |field: &str| format!("field_tvs.{set}.{field}");
        let deg = usize::try_from(field.integer(&name("deg"))).expect("small degree");
        assert_eq!(field.bytes(&name("res")).len(), lambda_bytes);
        assert_eq!(field.bytes(&name("unreduced")).len(), (2 * deg).div_ceil(8));
        assert_eq!(field.bytes(&name("reduced")).len(), (2 * deg).div_ceil(8));
        assert!(!field.bytes(&name("lhs")).is_empty());
    }
}

#[test]
fn owf_hash_crt_and_signature_vectors_have_the_expected_lengths() {
    let owf = Fixture::load("owf_tvs");
    for (set, lambda_bytes) in [
        ("FAEST_128F", 16_usize),
        ("FAEST_192F", 24),
        ("FAEST_256F", 32),
    ] {
        assert_eq!(owf.bytes(&format!("owf_tvs.{set}.key")).len(), lambda_bytes);
        // The AES input is one block; 192- and 256-bit outputs are two blocks.
        let blocks = if lambda_bytes == 16 { 1 } else { 2 };
        assert_eq!(owf.bytes(&format!("owf_tvs.{set}.input")).len(), 16);
        assert_eq!(
            owf.bytes(&format!("owf_tvs.{set}.output")).len(),
            16 * blocks
        );
    }
    for (set, lambda_bytes) in [
        ("FAEST_EM_128F", 16_usize),
        ("FAEST_EM_192F", 24),
        ("FAEST_EM_256F", 32),
    ] {
        for field in ["key", "input", "output"] {
            assert_eq!(
                owf.bytes(&format!("owf_tvs.{set}.{field}")).len(),
                lambda_bytes
            );
        }
    }

    let hashing = Fixture::load("universal_hashing_tvs");
    for lambda_bytes in [16_usize, 24, 32] {
        let lambda = lambda_bytes * 8;
        let leaf = |field: &str| format!("universal_hashing_tvs.leaf_hash_{lambda}.{field}");
        assert_eq!(hashing.bytes(&leaf("uhash")).len(), 3 * lambda_bytes);
        assert_eq!(hashing.bytes(&leaf("x")).len(), 4 * lambda_bytes);
        assert_eq!(hashing.bytes(&leaf("expected_h")).len(), 3 * lambda_bytes);
        let vole = |field: &str| format!("universal_hashing_tvs.vole_hash_{lambda}_7_tv.{field}");
        assert_eq!(hashing.integer(&vole("ell")), 5);
        assert_eq!(hashing.integer(&vole("d_zk")), 7);
        assert_eq!(hashing.integer(&vole("ell_prime")), 11);
        assert_eq!(hashing.bytes(&vole("sd")).len(), 8 * lambda_bytes + 8);
        assert_eq!(hashing.bytes(&vole("x")).len(), (11 + 4) * lambda_bytes);
        assert_eq!(hashing.bytes(&vole("digest")).len(), 4 * lambda_bytes);
    }

    let crt = Fixture::load("crt_vole_commit_tvs");
    for (set, lambda_bytes) in [
        ("128s", 16_usize),
        ("128f", 16),
        ("192s", 24),
        ("192f", 24),
        ("256s", 32),
        ("256f", 32),
        ("em_192s", 24),
        ("em_192f", 24),
    ] {
        let delta = crt.bytes(&format!("crt_tvs_{set}.delta_bytes"));
        assert!(delta.len() == lambda_bytes || delta.len() + 1 == lambda_bytes);
        assert_eq!(
            crt.bytes(&format!("crt_tvs_{set}.expected_crt_delta_bytes"))
                .len(),
            lambda_bytes
        );
    }

    let faest = Fixture::load("faest_tvs");
    assert_eq!(
        faest.bytes("faest_tvs.random_seed"),
        (0..16).collect::<Vec<u8>>()
    );
    assert_eq!(
        faest.bytes("faest_tvs.message"),
        b"This document describes and specifies the FAEST digital signature algorithm."
    );
    // Signature sizes of the twelve FAEST v3.0 parameter sets, in fixture order.
    let signatures = [
        ("faest_128s", 4066_usize),
        ("faest_128f", 5170),
        ("faest_192s", 9410),
        ("faest_192f", 11738),
        ("faest_256s", 16626),
        ("faest_256f", 20856),
        ("faest_em_128s", 3466),
        ("faest_em_128f", 4170),
        ("faest_em_192s", 7874),
        ("faest_em_192f", 9818),
        ("faest_em_256s", 14554),
        ("faest_em_256f", 18084),
    ];
    for (set, length) in signatures {
        assert_eq!(
            faest.bytes(&format!("faest_tvs.{set}.signature")).len(),
            length,
            "{set}"
        );
        assert!(!faest.bytes(&format!("faest_tvs.{set}.sk")).is_empty());
        assert!(!faest.bytes(&format!("faest_tvs.{set}.pk")).is_empty());
        assert!(!faest.bytes(&format!("faest_tvs.{set}.witness")).is_empty());
    }
}

#[test]
#[should_panic(expected = "has no entry named `prg_tvs.absent`")]
fn a_missing_name_panics_clearly() {
    let _ = Fixture::load("prg_tvs").bytes("prg_tvs.absent");
}
