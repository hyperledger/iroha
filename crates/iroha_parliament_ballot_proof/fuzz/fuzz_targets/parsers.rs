//! Coverage-guided fuzzing of bounded standalone statement, record and proof parsers.
#![no_main]

use std::sync::OnceLock;

use iroha_parliament_ballot_proof::{
    profile::{Profile, Role, Row},
    test_codec,
};
use iroha_zkp_vole::{codec, params::ProofParams, variant::Construction};
use libfuzzer_sys::fuzz_target;

fn statement(profile: &Profile, role: Role, data: &[u8]) {
    let canonical = match role {
        Role::Registration => test_codec::decode_registration(profile, data)
            .and_then(|value| test_codec::encode_registration(profile, &value)),
        Role::Vote => test_codec::decode_vote(profile, data)
            .and_then(|value| test_codec::encode_vote(profile, &value)),
    };
    if let Ok(canonical) = canonical {
        assert_eq!(canonical, data, "accepted statement is not canonical");
    }
}

fn proof(params: &ProofParams, data: &[u8]) {
    if let Ok(fields) = codec::decode_as(Construction::Extended, params, data) {
        let canonical = codec::encode_as(Construction::Extended, params, &fields)
            .expect("decoded fields have valid lengths");
        assert_eq!(canonical, data, "accepted proof is not canonical");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    // The selector is harness-only and never a production wire field.
    let row = usize::from(selector & 1);
    let role_index = usize::from((selector >> 1) & 1);
    let role = [Role::Registration, Role::Vote][role_index];
    static PROFILES: OnceLock<[Profile; 2]> = OnceLock::new();
    let profiles =
        PROFILES.get_or_init(|| Row::ALL.map(|row| Profile::new(row).expect("fixed row")));
    static PARAMS: OnceLock<[ProofParams; 4]> = OnceLock::new();
    let params = PARAMS.get_or_init(|| {
        std::array::from_fn(|i| {
            let role = [Role::Registration, Role::Vote][i % 2];
            ProofParams::new(
                Row::ALL[i / 2].vole(),
                role.witness_bits(),
                role.constraints(),
            )
            .expect("fixed relation")
        })
    });
    let profile = &profiles[row];
    let params = &params[2 * row + role_index];
    match (selector >> 2) % 3 {
        0 => statement(profile, role, bytes),
        1 => proof(params, bytes),
        _ => {
            if let Ok((encoded_statement, encoded_proof)) =
                test_codec::decode_record(profile, role, bytes)
            {
                statement(profile, role, encoded_statement);
                proof(params, encoded_proof);
                assert_eq!(
                    test_codec::encode_record(encoded_statement, encoded_proof).expect("bounded"),
                    bytes
                );
            }
        }
    }
});
