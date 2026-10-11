//! Parameter conformance: the key, signature, witness and component sizes of the
//! official FAEST v3.0.2 vectors match the twelve parameter rows.

mod common;

use common::Fixture;
use iroha_zkp_vole::params::{FAEST_PARAMETER_SETS, OwfKind};

const SET_NAMES: [&str; 12] = [
    "FAEST_128S",
    "FAEST_128F",
    "FAEST_192S",
    "FAEST_192F",
    "FAEST_256S",
    "FAEST_256F",
    "FAEST_EM_128S",
    "FAEST_EM_128F",
    "FAEST_EM_192S",
    "FAEST_EM_192F",
    "FAEST_EM_256S",
    "FAEST_EM_256F",
];

#[test]
fn signature_key_and_witness_sizes_match_the_official_vectors() {
    let fixture = Fixture::load("faest_tvs");
    for (set, name) in FAEST_PARAMETER_SETS.iter().zip(SET_NAMES) {
        let entry = |field: &str| format!("faest_tvs.{}.{field}", name.to_lowercase());
        assert_eq!(
            fixture.bytes(&entry("signature")).len(),
            set.signature_bytes(),
            "{name}"
        );
        assert_eq!(
            fixture.bytes(&entry("signature")).len(),
            set.proof().signature_bytes(),
            "{name}"
        );
        assert_eq!(
            fixture.bytes(&entry("pk")).len(),
            set.public_key_bytes(),
            "{name}"
        );
        assert_eq!(
            fixture.bytes(&entry("sk")).len(),
            set.secret_key_bytes(),
            "{name}"
        );
        assert_eq!(
            fixture.bytes(&entry("witness")).len(),
            set.proof().witness_bytes(),
            "{name}"
        );
    }
}

#[test]
fn component_sizes_match_the_official_vectors() {
    let bavc = Fixture::load("bavc_tvs");
    let owf = Fixture::load("owf_tvs");
    for (set, name) in FAEST_PARAMETER_SETS.iter().zip(SET_NAMES) {
        let vole = set.vole();
        assert_eq!(
            bavc.u16_list(&format!("bavc_tvs.{name}.i_delta")).len(),
            vole.tau(),
            "{name}"
        );
        for (i, index) in bavc
            .u16_list(&format!("bavc_tvs.{name}.i_delta"))
            .into_iter()
            .enumerate()
        {
            assert!(
                usize::from(index) < vole.leaves_of(i).expect("i < tau"),
                "{name}"
            );
        }
        assert_eq!(
            bavc.bytes(&format!("bavc_tvs.{name}.leaf_commit_expected_com"))
                .len(),
            vole.leaf_commitment_bytes(),
            "{name}"
        );
        assert_eq!(
            bavc.names()
                .contains(&format!("bavc_tvs.{name}.leaf_commit_uhash")),
            set.owf().kind() == OwfKind::Aes
        );
        if name.ends_with('F') {
            let entry = |field: &str| format!("owf_tvs.{name}.{field}");
            assert_eq!(owf.bytes(&entry("key")).len(), vole.lambda().bytes());
            assert_eq!(owf.bytes(&entry("input")).len(), set.owf().input_bytes());
            assert_eq!(owf.bytes(&entry("output")).len(), set.owf().output_bytes());
        }
    }
}
