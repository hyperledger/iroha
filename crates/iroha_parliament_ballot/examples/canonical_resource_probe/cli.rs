//! Strict standalone CLI and out-of-interval reporting for the canonical-input probe.

use std::{
    ffi::{OsStr, OsString},
    path::Path,
};

use iroha_data_model::{NetworkId, governance::types::BodyInstanceId};
use norito::json::JsonSerialize;

use super::{arena, budget, fatal, staging, workspace};

const USAGE: &str = "canonical_resource_probe ENVELOPE CONTEXT --network CHECKED_HASH_LITERAL --body LOWERCASE_HEX32 --fatal-fd FD [--heap-limit N] [--units N] [--input-bytes N]\nThe two files contain complete canonical Enc frames. Either positional argument may be --borrowed-oversize to exercise its independent cap+1 borrow. FD is a fresh zeroed owner-only unlinked writable native page inherited from the supervisor. This candidate-only proof-validity diagnostic has no protocol effects or qualification authority.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input<'a> {
    Path(&'a Path),
    Oversize,
}

impl<'a> Input<'a> {
    fn parse(value: &'a OsStr) -> Self {
        if value == "--borrowed-oversize" {
            Self::Oversize
        } else {
            Self::Path(Path::new(value))
        }
    }

    fn retrieve(self, cap: usize) -> Result<Vec<u8>, staging::StageError> {
        match self {
            Self::Path(path) => staging::from_path(path, cap),
            // Allocated in the supervisor. The worker must refuse the original
            // borrow independently, before copying or decoding either input.
            Self::Oversize => Ok(vec![0; cap + 1]),
        }
    }
}

#[derive(Debug)]
struct Arguments<'a> {
    envelope: Input<'a>,
    context: Input<'a>,
    network: NetworkId,
    body: BodyInstanceId,
    fatal_fd: i32,
    heap_limit: usize,
    units: u64,
    input_bytes: u64,
}

fn unsigned(value: &OsStr) -> Result<u64, ()> {
    let text = value.to_str().ok_or(())?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    text.parse().map_err(|_| ())
}

fn parse(args: &[OsString]) -> Result<Arguments<'_>, ()> {
    if args.len() < 9 || !(args.len() - 3).is_multiple_of(2) {
        return Err(());
    }
    let mut network = None;
    let mut body = None;
    let mut fatal_fd = None;
    let mut heap_limit = arena::HEAP_BYTES;
    let mut units = budget::VERIFICATION_UNITS;
    let mut input_bytes = budget::MAX_INPUT_BYTES as u64;
    let mut seen = 0u8;
    for pair in args[3..].chunks_exact(2) {
        let bit = match pair[0].to_str() {
            Some("--network") => {
                network = Some(pair[1].to_str().ok_or(())?.parse().map_err(|_| ())?);
                1
            }
            Some("--body") => {
                body = Some(
                    BodyInstanceId::from_hex_str(pair[1].to_str().ok_or(())?).map_err(|_| ())?,
                );
                2
            }
            Some("--fatal-fd") => {
                let fd = i32::try_from(unsigned(&pair[1])?).map_err(|_| ())?;
                if fd < 3 {
                    return Err(());
                }
                fatal_fd = Some(fd);
                4
            }
            Some("--heap-limit") => {
                heap_limit = usize::try_from(unsigned(&pair[1])?).map_err(|_| ())?;
                if heap_limit > arena::HEAP_BYTES {
                    return Err(());
                }
                8
            }
            Some("--units") => {
                units = unsigned(&pair[1])?;
                16
            }
            Some("--input-bytes") => {
                input_bytes = unsigned(&pair[1])?;
                32
            }
            _ => return Err(()),
        };
        if seen & bit != 0 {
            return Err(());
        }
        seen |= bit;
    }
    Ok(Arguments {
        envelope: Input::parse(&args[1]),
        context: Input::parse(&args[2]),
        network: network.ok_or(())?,
        body: body.ok_or(())?,
        fatal_fd: fatal_fd.ok_or(())?,
        heap_limit,
        units,
        input_bytes,
    })
}

#[derive(JsonSerialize)]
struct StagingReport {
    outcome: &'static str,
    verifier_stage: &'static str,
    input_kind: &'static str,
    charged_units: u64,
    charged_bytes: u64,
    arena_allocations: usize,
    arena_enforced: bool,
    validity_only: bool,
    protocol_effect: bool,
    complete_workspace_certificate: bool,
    profile_qualified: bool,
}

fn staging_failure(error: staging::StageError, input_kind: &'static str) -> i32 {
    // All staging failures occur before run/reservation. Oversize regular files
    // are refused here; --borrowed-oversize reaches the separate worker guard.
    let report = StagingReport {
        outcome: "input_error",
        verifier_stage: error.label(),
        input_kind,
        charged_units: 0,
        charged_bytes: 0,
        arena_allocations: 0,
        arena_enforced: false,
        validity_only: true,
        protocol_effect: false,
        complete_workspace_certificate: false,
        profile_qualified: false,
    };
    println!(
        "{}",
        norito::json::to_json(&report).expect("fixed staging report")
    );
    3
}

pub fn run() -> i32 {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && args[1] == "--help" {
        println!("{USAGE}");
        return 0;
    }
    let Ok(args) = parse(&args) else {
        eprintln!("{USAGE}");
        return 3;
    };
    if let Err(fatal::FatalError(operation, code)) = fatal::install(args.fatal_fd) {
        eprintln!("fatal control setup failed: {operation} ({code})");
        return 4;
    }
    let envelope = match args.envelope.retrieve(budget::ENVELOPE_MAX) {
        Ok(bytes) => bytes,
        Err(error) => return staging_failure(error, "envelope"),
    };
    let context = match args.context.retrieve(budget::CONTEXT_MAX) {
        Ok(bytes) => bytes,
        Err(error) => return staging_failure(error, "context"),
    };
    // No concurrent application work. Both immutable owners stay live through
    // synchronous worker join; the separate arena copies are dropped inside it.
    let result = workspace::run(workspace::Options {
        envelope: &envelope,
        context: &context,
        network: args.network,
        body: args.body,
        heap_limit: args.heap_limit,
        units: args.units,
        input_bytes: args.input_bytes,
    });
    drop(context);
    drop(envelope);
    match result {
        Ok((report, exit)) => {
            println!(
                "{}",
                norito::json::to_json(&report).expect("fixed worker report")
            );
            exit
        }
        Err(native_error) => {
            eprintln!(
                "canonical worker setup failed: {} ({})",
                native_error.0, native_error.1
            );
            4
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        vec![
            "canonical_resource_probe".into(),
            "envelope".into(),
            "context".into(),
            "--network".into(),
            norito::literal::format("hash", &"11".repeat(32)).into(),
            "--body".into(),
            "03".repeat(32).into(),
            "--fatal-fd".into(),
            "7".into(),
        ]
    }

    #[test]
    fn explicit_identity_and_defaults_are_preserved() {
        let args = arguments();
        let parsed = parse(&args).unwrap();
        assert_eq!(parsed.envelope, Input::Path(Path::new("envelope")));
        assert_eq!(parsed.context, Input::Path(Path::new("context")));
        assert_eq!(parsed.network.to_string(), args[4].to_str().unwrap());
        assert_eq!(parsed.body, BodyInstanceId::new([3; 32]));
        assert_eq!(
            (
                parsed.fatal_fd,
                parsed.units,
                parsed.input_bytes,
                parsed.heap_limit
            ),
            (7, 1, 425_984, 32 * 1024 * 1024)
        );
        let mut args = arguments();
        args.extend(
            ["--heap-limit", "0", "--units", "0", "--input-bytes", "0"].map(OsString::from),
        );
        let parsed = parse(&args).unwrap();
        assert_eq!(
            (parsed.heap_limit, parsed.units, parsed.input_bytes),
            (0, 0, 0)
        );
    }

    #[test]
    fn missing_duplicate_unknown_and_noncanonical_arguments_refuse() {
        let args = arguments();
        for end in 0..args.len() {
            assert!(parse(&args[..end]).is_err());
        }
        for (flag, value) in [
            ("--network", args[4].to_str().unwrap()),
            ("--body", args[6].to_str().unwrap()),
            ("--fatal-fd", "8"),
            ("--unknown", "1"),
            ("--heap-limit", "33554433"),
            ("--units", "-1"),
            ("--units", "+1"),
            ("--input-bytes", "18446744073709551616"),
        ] {
            let mut changed = args.clone();
            changed.extend([flag.into(), value.into()]);
            assert!(parse(&changed).is_err(), "{flag} {value}");
        }
        for (index, value) in [(4, "testnet"), (6, "03"), (8, "2"), (8, "2147483648")] {
            let mut changed = args.clone();
            changed[index] = value.into();
            assert!(parse(&changed).is_err());
        }
        let mut changed = args.clone();
        changed[6] = "AB".repeat(32).into();
        assert!(parse(&changed).is_err());
    }

    #[test]
    fn oversize_borrows_are_separate_and_file_escape_is_literal() {
        assert_eq!(
            Input::parse(OsStr::new("--borrowed-oversize")),
            Input::Oversize
        );
        assert_eq!(
            Input::parse(OsStr::new("./--borrowed-oversize")),
            Input::Path(Path::new("./--borrowed-oversize"))
        );
        for cap in [budget::ENVELOPE_MAX, budget::CONTEXT_MAX] {
            assert_eq!(Input::Oversize.retrieve(cap).unwrap().len(), cap + 1);
        }
        for bad in ["", "-1", "+1", " 1", "1 ", "1.0", "18446744073709551616"] {
            assert!(unsigned(OsStr::new(bad)).is_err());
        }
        assert_eq!(unsigned(OsStr::new("18446744073709551615")), Ok(u64::MAX));
    }
}
