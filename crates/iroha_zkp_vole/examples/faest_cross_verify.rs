//! File-based diagnostic bridge to the twelve reference FAEST parameter sets.
//!
//! Used by `tests/fixtures/faest_v3_0_2/cross_verify_upstream.py` to exchange
//! fresh signatures with the unmodified pinned upstream C implementation.
//! Inputs are public deterministic test material, never operational keys.

use std::{env, error::Error, fs, process::ExitCode};

use iroha_zkp_vole::{
    codec::Field,
    faest::{self, SecretKey},
    params::{
        FAEST_128F, FAEST_128S, FAEST_192F, FAEST_192S, FAEST_256F, FAEST_256S, FAEST_EM_128F,
        FAEST_EM_128S, FAEST_EM_192F, FAEST_EM_192S, FAEST_EM_256F, FAEST_EM_256S, FaestParams,
    },
};

fn parameters(name: &str) -> Option<&'static FaestParams> {
    match name {
        "faest_128s" => Some(&FAEST_128S),
        "faest_128f" => Some(&FAEST_128F),
        "faest_192s" => Some(&FAEST_192S),
        "faest_192f" => Some(&FAEST_192F),
        "faest_256s" => Some(&FAEST_256S),
        "faest_256f" => Some(&FAEST_256F),
        "faest_em_128s" => Some(&FAEST_EM_128S),
        "faest_em_128f" => Some(&FAEST_EM_128F),
        "faest_em_192s" => Some(&FAEST_EM_192S),
        "faest_em_192f" => Some(&FAEST_EM_192F),
        "faest_em_256s" => Some(&FAEST_EM_256S),
        "faest_em_256f" => Some(&FAEST_EM_256F),
        _ => None,
    }
}

fn run(args: &[String]) -> Result<u8, Box<dyn Error>> {
    if args.len() == 1 && args[0] == "identity" {
        println!(
            "{}",
            if cfg!(feature = "accel") {
                "accel"
            } else {
                "portable"
            }
        );
        return Ok(0);
    }
    if args.len() < 2 {
        return Err("expected identity, public-key SET SK PK, sign SET SK MSG RHO SIG, or verify SET PK MSG SIG".into());
    }
    let set = parameters(&args[1]).ok_or("unknown reference parameter set")?;
    match (args[0].as_str(), args.len()) {
        ("layout", 2) => {
            for field in Field::ALL {
                println!(
                    "{field:?} {} {}",
                    field.offset(set.proof()),
                    field.bytes(set.proof())
                );
            }
        }
        ("public-key", 4) => {
            let sk = SecretKey::from_bytes(set, &fs::read(&args[2])?)?;
            fs::write(&args[3], sk.public_key().as_bytes())?;
        }
        ("sign", 6) => {
            let sk = SecretKey::from_bytes(set, &fs::read(&args[2])?)?;
            let signature = sk.sign(&fs::read(&args[3])?, &fs::read(&args[4])?)?;
            fs::write(&args[5], signature)?;
        }
        ("verify", 5) => {
            let result = faest::verify(
                set,
                &fs::read(&args[2])?,
                &fs::read(&args[3])?,
                &fs::read(&args[4])?,
            );
            if let Err(error) = result {
                println!("rejected: {error}");
                return Ok(1);
            }
            println!("accepted");
        }
        _ => return Err("wrong operation or argument count".into()),
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("diagnostic error: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_rejects_unknown_sets_and_bad_invocations() {
        assert!(parameters("ballot").is_none());
        assert!(parameters("faest_128s").is_some());
        assert!(parameters("faest_em_256f").is_some());
        assert!(run(&[]).is_err());
        assert!(run(&["verify".into(), "faest_128s".into()]).is_err());
        assert_eq!(run(&["identity".into()]).unwrap(), 0);
    }
}
