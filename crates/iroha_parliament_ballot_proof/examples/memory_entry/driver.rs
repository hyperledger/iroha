//! Separately built in-memory ballot qualification entry, never a shipping API.
//! The preparation receipt pins reused modules and the exact worker derivation.
#![allow(unsafe_code)]

#[cfg(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux")))]
#[path = "../resource_contract/arena.rs"]
mod arena;
#[cfg(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux")))]
#[path = "../resource_contract/budget.rs"]
mod budget;
#[cfg(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux")))]
#[path = "../resource_contract/native.rs"]
mod native;
#[cfg(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux")))]
mod staging;
#[cfg(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux")))]
#[path = "generated_workspace.rs"]
mod workspace;

#[cfg(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux")))]
mod application {
    use std::{ffi::OsString, path::Path};
    use iroha_parliament_ballot_proof::profile::{Role, Row};
    use super::{arena, budget, native, staging, workspace};

    const USAGE: &str = "memory_entry candidate|comparator registration|vote INPUT [--heap-limit N] [--units N] [--input-bytes N]\nRetrieval happens before charged verification; this diagnostic does not qualify production.";

    struct Arguments<'a> {
        row: Row,
        role: Role,
        path: &'a Path,
        heap_limit: usize,
        units: u64,
        input_bytes: u64,
    }

    fn parse(args: &[OsString]) -> Result<Arguments<'_>, ()> {
        if args.len() < 4 || !(args.len() - 4).is_multiple_of(2) {
            return Err(());
        }
        let mut result = Arguments {
            row: match args[1].to_str() { Some("candidate") => Row::Candidate, Some("comparator") => Row::Comparator, _ => return Err(()) },
            role: match args[2].to_str() { Some("registration") => Role::Registration, Some("vote") => Role::Vote, _ => return Err(()) },
            path: Path::new(&args[3]),
            heap_limit: arena::HEAP_BYTES,
            units: budget::VERIFICATION_UNITS,
            input_bytes: budget::MAX_INPUT_BYTES as u64,
        };
        let mut seen = 0u8;
        for pair in args[4..].chunks_exact(2) {
            let value = pair[1].to_str().and_then(|s| s.parse::<u64>().ok()).ok_or(())?;
            let bit = match pair[0].to_str() {
                Some("--heap-limit") => { result.heap_limit = usize::try_from(value).map_err(|_| ())?; 1 },
                Some("--units") => { result.units = value; 2 },
                Some("--input-bytes") => { result.input_bytes = value; 4 },
                _ => return Err(()),
            };
            if seen & bit != 0 { return Err(()); }
            seen |= bit;
        }
        Ok(result)
    }

    #[derive(norito::json::JsonSerialize)]
    struct StagingReport {
        outcome: &'static str,
        verifier_stage: &'static str,
        charged_units: u64,
        charged_bytes: u64,
        complete_workspace_certificate: bool,
        profile_qualified: bool,
    }

    /// Parse the standalone request, stage and close the file, then join exactly
    /// one bounded worker before releasing its borrowed caller input.
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
        let staged = match staging::from_path(args.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let too_large = error == staging::StageError::TooLarge;
                println!("{}", norito::json::to_json(&StagingReport {
                    outcome: if too_large { "admission_rejected" } else { "input_error" },
                    verifier_stage: error.label(),
                    charged_units: 0,
                    charged_bytes: 0,
                    complete_workspace_certificate: false,
                    profile_qualified: false,
                }).expect("fixed staging report"));
                return if too_large { 2 } else { 3 };
            }
        };
        // File ownership ended in from_path. `staged` is immutable throughout
        // synchronous run/join; only its bounded copy belongs to the arena.
        let result = workspace::run(workspace::Options {
            row: args.row,
            role: args.role,
            record: &staged,
            heap_limit: args.heap_limit,
            units: args.units,
            input_bytes: args.input_bytes,
        });
        // Every returning run path has joined any started worker and cleared
        // ACTIVE. Fatal worker exits do not promise Rust Drop cleanup.
        drop(staged);
        match result {
            Ok((report, exit)) => {
                println!("{}", norito::json::to_json(&report).expect("fixed worker report"));
                exit
            }
            Err(native::NativeError(operation, code)) => {
                eprintln!("memory worker setup failed: {operation} ({code})");
                4
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn arguments(values: &[&str]) -> Vec<OsString> {
            values.iter().map(OsString::from).collect()
        }
        #[test]
        fn parser_uses_explicit_rows_roles_and_bounded_defaults() {
            let args = arguments(&["memory_entry", "candidate", "vote", "input"]);
            let parsed = parse(&args).expect("valid request");
            assert_eq!(parsed.row, Row::Candidate);
            assert_eq!(parsed.role, Role::Vote);
            assert_eq!(parsed.path, Path::new("input"));
            assert_eq!(parsed.heap_limit, arena::HEAP_BYTES);
            assert_eq!(parsed.units, 1);
            assert_eq!(parsed.input_bytes, 425984);
            let args = arguments(&["memory_entry", "comparator", "registration", "input", "--heap-limit", "1", "--units", "0", "--input-bytes", "8"]);
            let parsed = parse(&args).expect("explicit refusal controls");
            assert_eq!((parsed.heap_limit, parsed.units, parsed.input_bytes), (1, 0, 8));
        }
        #[test]
        fn parser_rejects_unknown_duplicate_and_malformed_options() {
            for args in [
                vec!["memory_entry"],
                vec!["memory_entry", "unknown", "vote", "input"],
                vec!["memory_entry", "candidate", "unknown", "input"],
                vec!["memory_entry", "candidate", "vote", "input", "--units"],
                vec!["memory_entry", "candidate", "vote", "input", "--units", "-1"],
                vec!["memory_entry", "candidate", "vote", "input", "--other", "1"],
                vec!["memory_entry", "candidate", "vote", "input", "--units", "1", "--units", "2"],
            ] { assert!(parse(&arguments(&args)).is_err()); }
        }
    }
}

#[cfg(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux")))]
fn main() {
    std::process::exit(application::run());
}

#[cfg(not(all(target_pointer_width = "64", any(target_os = "macos", target_os = "linux"))))]
fn main() {
    eprintln!("memory_entry supports only 64-bit Linux or macOS; no unbounded fallback");
    std::process::exit(4);
}
