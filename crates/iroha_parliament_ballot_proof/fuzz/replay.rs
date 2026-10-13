//! Replay the saved parser corpus and digest its syntactic outcomes in filename order.

use std::{fmt::Write as _, path::PathBuf};

use iroha_parliament_ballot_proof::{
    profile::{Profile, Role, Row},
    test_codec,
};
use iroha_zkp_vole::{codec, hash::Sha3_512, params::ProofParams, variant::Construction};

fn statement(profile: &Profile, role: Role, data: &[u8]) -> bool {
    let canonical = match role {
        Role::Registration => test_codec::decode_registration(profile, data)
            .and_then(|value| test_codec::encode_registration(profile, &value)),
        Role::Vote => test_codec::decode_vote(profile, data)
            .and_then(|value| test_codec::encode_vote(profile, &value)),
    };
    canonical.is_ok_and(|canonical| {
        assert_eq!(canonical, data, "accepted statement is not canonical");
        true
    })
}

fn proof(params: &ProofParams, data: &[u8]) -> bool {
    codec::decode_as(Construction::Extended, params, data).is_ok_and(|fields| {
        assert_eq!(
            codec::encode_as(Construction::Extended, params, &fields).expect("decoded lengths"),
            data,
            "accepted proof is not canonical"
        );
        true
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: replay CORPUS_DIR")?;
    let mut paths: Vec<PathBuf> = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()?;
    paths.sort();
    let profiles = Row::ALL.map(|row| Profile::new(row).expect("fixed row"));
    let params: [ProofParams; 4] = std::array::from_fn(|i| {
        let role = Role::ALL[i % 2];
        ProofParams::new(
            Row::ALL[i / 2].vole(),
            role.witness_bits(),
            role.constraints(),
        )
        .expect("fixed relation")
    });
    let mut digest = Sha3_512::new();
    digest.update(b"parliament/parser-fuzz-replay/v1");
    let mut outcomes = [0u64; 8];
    for path in &paths {
        if !path.is_file() || path.metadata()?.len() > 400_000 {
            return Err("corpus entries must be regular files of at most 400000 bytes".into());
        }
        let data = std::fs::read(path)?;
        let outcome = data.split_first().map_or(0, |(&selector, bytes)| {
            let row = usize::from(selector & 1);
            let role_index = usize::from((selector >> 1) & 1);
            let role = Role::ALL[role_index];
            let profile = &profiles[row];
            let params = &params[2 * row + role_index];
            match (selector >> 2) % 3 {
                0 => u8::from(statement(profile, role, bytes)),
                1 => u8::from(proof(params, bytes)),
                _ => test_codec::decode_record(profile, role, bytes).map_or(0, |(stmt, raw)| {
                    assert_eq!(
                        test_codec::encode_record(stmt, raw).expect("bounded"),
                        bytes
                    );
                    1 | (u8::from(statement(profile, role, stmt)) << 1)
                        | (u8::from(proof(params, raw)) << 2)
                }),
            }
        });
        digest.update(&u64::try_from(data.len())?.to_le_bytes());
        let mut input = Sha3_512::new();
        input.update(&data);
        digest.update(&input.finalize());
        digest.update(&[outcome]);
        outcomes[usize::from(outcome)] += 1;
    }
    let mut hexadecimal = String::new();
    for byte in digest.finalize() {
        write!(hexadecimal, "{byte:02x}")?;
    }
    println!(
        "cases={} syntactic_outcome_histogram={outcomes:?} sha3_512={hexadecimal}",
        paths.len()
    );
    Ok(())
}
